rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_64_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_64_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b399b662facb12f2ab8f3c90f5149ec64bfbd51094d213897161bd1def0142d9"

  strings:
    $s1 = "Giz kodota tiziwibumap<Pegis lul jefimiwifeyopud remosacuhuyige cimeganoregiwu cuya" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}