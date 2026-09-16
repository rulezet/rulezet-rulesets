rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_aaT6Wyj_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@aaT6Wyj_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4347ef2deb93c96a07aa919948e5feacc6028f0e2838ff665ae61065bdb7d2f2"

  strings:
    $s1 = ":whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}