rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_30_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22bce1ba9a887643a529dcfe054e21edcada6c6ccb4cec81a7a8b67a5827fa1b"

  strings:
    $s1 = "Jsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}