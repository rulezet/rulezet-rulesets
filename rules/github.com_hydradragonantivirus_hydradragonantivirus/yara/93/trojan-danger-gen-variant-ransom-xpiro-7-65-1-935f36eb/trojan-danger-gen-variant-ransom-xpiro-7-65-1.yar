rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_65_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_65_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18650b3d2f7df668603e68a4f7014f57d8eddafd41958da3e2bdb11a2df80624"

  strings:
    $s1 = "j9Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}