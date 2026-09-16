rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_22_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2961a7400c281f7159382dabb4205add2109e22e177540af0d029ae25a6eb2ae"

  strings:
    $s1 = "]l&Mome%" fullword ascii
    $s2 = "=]l&Mome%" fullword ascii
    $s3 = "?Mome%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}