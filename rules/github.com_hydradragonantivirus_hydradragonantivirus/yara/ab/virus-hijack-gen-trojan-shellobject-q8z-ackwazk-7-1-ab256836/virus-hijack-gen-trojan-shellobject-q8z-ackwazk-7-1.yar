rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aCkwazk_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6801e5563611e538ca3d676c8349a81c8a496bee0f6041b60740c28e8fd7dd10"

  strings:
    $s1 = "bEanO&" fullword ascii
    $s2 = "SupA*m" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}