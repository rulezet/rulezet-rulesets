rule miner_g_p_0 {
  meta:
    description = "miner-exe - from files g, p"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-22"
    hash1       = "7fe9d6d8b9390020862ca7dc9e69c1e2b676db5898e4bfad51d66250e9af3eaf"
    hash2       = "63210b24f42c05b2c5f8fd62e98dba6de45c7d751a2e55700d22983772886017"

  strings:
    $s1  = "TLS generation counter wrapped!  Please report as described in <http://www.debian.org/Bugs/>." fullword ascii
    $s2  = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii
    $s3  = "relocation processing: %s%s" fullword ascii
    $s4  = "ELF load command address/offset not properly aligned" fullword ascii
    $s5  = "version == ((void *)0) || (flags & ~(DL_LOOKUP_ADD_DEPENDENCY | DL_LOOKUP_GSCOPE_LOCK)) == 0" fullword ascii
    $s6  = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii
    $s7  = "__pthread_mutex_lock" fullword ascii
    $s8  = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 16384 - 3) / 4" fullword ascii
    $s9  = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 1024 - 3) / 4" fullword ascii
    $s10 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-1021) - 53) / 4" fullword ascii
    $s11 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-125) - 24) / 4" fullword ascii
    $s12 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-16381) - 64) / 4" fullword ascii
    $s13 = "headmap.len == archive_stat.st_size" fullword ascii
    $s14 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 4932 - 1)" fullword ascii
    $s15 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 38 - 1)" fullword ascii
    $s16 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 308 - 1)" fullword ascii
    $s17 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-307) - 53)" fullword ascii
    $s18 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-4931) - 64)" fullword ascii
    $s19 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-37) - 24)" fullword ascii
    $s20 = "(char *) ((void*)((char*)(p) + 2*(sizeof(size_t)))) + 4 * (sizeof(size_t)) <= paligned_mem" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 9000KB and (8 of them)
    ) or (all of them)
}