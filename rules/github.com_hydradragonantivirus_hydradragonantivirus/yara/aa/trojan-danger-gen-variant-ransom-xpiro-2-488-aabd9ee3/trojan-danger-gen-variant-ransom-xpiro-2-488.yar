rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_488 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_488.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbc8f913020e777b719a2faf1cd1e6919e82f772c4afa413564526b19cbbb21a"

  strings:
    $s1 = "vV[TRap?<nau" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}