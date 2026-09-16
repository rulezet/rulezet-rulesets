rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_133 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_133.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e29ae80d13f44db98678525fd260fc1d1454d7cff515cfb7b240170c8ad8f86"

  strings:
    $s1 = "TRap?<RRRRRRnS__R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}