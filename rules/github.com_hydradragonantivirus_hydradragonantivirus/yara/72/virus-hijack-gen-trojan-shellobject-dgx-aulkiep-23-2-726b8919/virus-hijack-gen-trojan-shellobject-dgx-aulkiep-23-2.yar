rule Virus_Hijack_Gen_Trojan_ShellObject_dGX_aulKiep_23_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dGX@aulKiep_23_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8654fd5274321e955f8560b05177a57b1e7210cb893aca3d451902331ba9c689"

  strings:
    $s1 = "K)MEse:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}