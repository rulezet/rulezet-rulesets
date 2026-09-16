rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_46_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_46_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d884f2dcc7e2e11c73c9d5aaf6afdd99db8013ea895ed0a65c9a8766e239644"

  strings:
    $s1 = " Setup\\InstalAd Component<" fullword ascii
    $s2 = "r\\Shell Fold" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}