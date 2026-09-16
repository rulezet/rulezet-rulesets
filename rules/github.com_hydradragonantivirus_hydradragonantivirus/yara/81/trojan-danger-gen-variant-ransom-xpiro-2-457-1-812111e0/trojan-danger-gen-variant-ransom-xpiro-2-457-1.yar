rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_457_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_457_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d37f154d821cf96ffea3a5edad1efa1f5bd928ea8fd937bbef2c19e2656a89ae"

  strings:
    $s1 = " Setup\\InstalAd Component<" fullword ascii
    $s2 = "r\\Shell Fold" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}