rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_78_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_78_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aea40867f16ec495f50e0b65293267bd1c6c5c58e9920898968186ff32fa3ae5"

  strings:
    $s1 = "NForders during any 12 month period." fullword ascii
    $s2 = "drag>%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}