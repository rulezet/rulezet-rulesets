rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_486_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_486_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caaf6c13094d5b58d36b80f39cea630d822c8172ee9ad37598e172cb41c7102c"

  strings:
    $s1 = "ZUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}