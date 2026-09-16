rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_63_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_63_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97656adc7be62af244c4ef95bdfa3672a40c98e77c6221cae7cc0832a3d4195f"

  strings:
    $s1 = ":bUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}