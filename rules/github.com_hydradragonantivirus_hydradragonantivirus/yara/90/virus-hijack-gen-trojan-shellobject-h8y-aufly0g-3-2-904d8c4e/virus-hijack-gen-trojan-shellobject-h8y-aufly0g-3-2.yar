rule Virus_Hijack_Gen_Trojan_ShellObject_h8Y_auFLy0g_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8Y@auFLy0g_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5705e566a779c766a1398ef1324ce5c0e3062e39078d19bc350ada001144478"

  strings:
    $s1 = "Rich!l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}