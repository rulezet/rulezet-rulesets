rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05169946e28140fafab6d84371b5c83b731ee6d4013fe6f31cbda245f0a9b062"

  strings:
    $s1 = "7-hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}