rule _home_hawk_infected_12_22_19_shell1_work1_34esd23 {
  meta:
    description = "work1 - file 34esd23.zip"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "8862eefed0ef325212a49f8617a396a7ef3b6e5d05cddeda998dbf1ae834be91"

  strings:
    $s1  = "papkaa17/g336803.txt" fullword ascii
    $s2  = "papkaa17/g757230.txt" fullword ascii
    $s3  = "papkaa17/g554038.txt" fullword ascii
    $s4  = "papkaa17/g864401.txt" fullword ascii
    $s5  = "papkaa17/g380118.txt" fullword ascii
    $s6  = "papkaa17/g200125.txt" fullword ascii
    $s7  = "papkaa17/g365278.txt" fullword ascii
    $s8  = "papkaa17/g895434.txt" fullword ascii
    $s9  = "papkaa17/g554066.txt" fullword ascii
    $s10 = "system.phpu" fullword ascii
    $s11 = "system.phpPK" fullword ascii

  condition:
    (uint16(0) == 0x4b50 and
      filesize < 200KB and
      (8 of them)
    ) or (all of them)
}