rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_138_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_138_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "261ad2454b554a4c7d8a1eb67b1be13b6700a347ac158ab3103f8fd470e55a05"

  strings:
    $s1 = "'University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}