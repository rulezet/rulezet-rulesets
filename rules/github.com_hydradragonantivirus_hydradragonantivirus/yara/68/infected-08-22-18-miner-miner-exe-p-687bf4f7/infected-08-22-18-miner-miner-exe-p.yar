rule infected_08_22_18_miner_miner_exe_p {
  meta:
    description = "miner-exe - file p"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-22"
    hash1       = "63210b24f42c05b2c5f8fd62e98dba6de45c7d751a2e55700d22983772886017"

  strings:
    $x1  = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
    $s2  = "(-(e)) != 35 || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii
    $s3  = "s->d1->w_msg_hdr.msg_len + ((s->version == DTLS1_VERSION) ? DTLS1_CCS_HEADER_LENGTH : 3) == (unsigned int)s->init_num" fullword ascii
    $s4  = "Rewinding stream by : %d bytes on url %s (size = %lld, maxdownload = %lld, bytecount = %lld, nread = %d)" fullword ascii
    $s5  = "((mutex)->__data.__kind & 127) == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
    $s6  = "*(sizeof(size_t)) < __alignof__ (long double) ? __alignof__ (long double) : 2 *(sizeof(size_t))) - 1)) & ~((2 *(sizeof(size_t))" fullword ascii
    $s7  = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
    $s8  = "type == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
    $s9  = "(mutex->__data.__kind & PTHREAD_MUTEX_ROBUST_NORMAL_NP) == 0" fullword ascii
    $s10 = "(mutex->__data.__kind & PTHREAD_MUTEX_PRIO_INHERIT_NP) != 0" fullword ascii
    $s11 = "compiler: gcc -I. -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -m64 -DL_ENDIAN -DTERMIO -g -O2 -" ascii
    $s12 = "* (4 * 1024 * 1024 * sizeof(long))) - 1)))->ar_ptr : &main_arena)" fullword ascii
    $s13 = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
    $s14 = "TLS generation counter wrapped!  Please report as described in <http://www.debian.org/Bugs/>." fullword ascii
    $s15 = "__pthread_mutex_unlock_usercnt" fullword ascii
    $s16 = "*** Error in `%s': %s: 0x%s ***" fullword ascii
    $s17 = "== 1) ? __builtin_strcmp (&zone_names[info->idx], __tzname[tp->tm_isdst]) : (- (__extension__ ({ const unsigned char *__s2 = (c" fullword ascii
    $s18 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
    $s19 = "FTP: login denied" fullword ascii
    $s20 = "__pthread_mutex_cond_lock_adjust" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 9000KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}