rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_521_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_521_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be55d27749c0a599e0478259a127f81316e576c0d6d09a11f393493e932e7f56"

  strings:
    $s1 = "spurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}