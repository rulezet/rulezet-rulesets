rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_312_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_312_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54d5c9917226dee493925ae931ba7c7e577d78142113f25ed2d622e63ac3bbe8"

  strings:
    $s1 = "F`software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}