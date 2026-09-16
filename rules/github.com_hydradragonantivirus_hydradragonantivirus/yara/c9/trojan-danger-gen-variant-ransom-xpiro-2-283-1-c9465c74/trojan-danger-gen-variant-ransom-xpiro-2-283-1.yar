rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_283_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_283_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90bdb15e92ed35341196cca797e8b8fe301f976318f599694e256984fddae5d4"

  strings:
    $s1 = "breaching party continues reasonable efforts to cure the breach. You agree that if you " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}