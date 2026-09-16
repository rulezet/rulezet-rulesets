rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCMzZah_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCMzZah_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "899a3344b39b3aaec6d1b6bad223162398eb152c27e2a67d6d30838280c58486"

  strings:
    $s1 = "+orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}