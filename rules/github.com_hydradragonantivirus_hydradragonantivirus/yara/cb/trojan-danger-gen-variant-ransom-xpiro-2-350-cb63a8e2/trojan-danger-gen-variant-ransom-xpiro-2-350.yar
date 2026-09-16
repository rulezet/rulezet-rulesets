rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_350 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_350.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cff93f857ec04d71691099f323f6aea0f873cb5db95e3c15b163c30f28cef63"

  strings:
    $s1 = "TaTe]]]T" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}