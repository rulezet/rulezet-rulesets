rule Virus_Hijack_Gen_Trojan_ShellObject_h8Y_auFLy0g_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8Y@auFLy0g_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84a777d7a5184109ae925f48954d1d07248b1b5c030acfbc072d66c548bac06c"

  strings:
    $s1 = "Rich!l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}