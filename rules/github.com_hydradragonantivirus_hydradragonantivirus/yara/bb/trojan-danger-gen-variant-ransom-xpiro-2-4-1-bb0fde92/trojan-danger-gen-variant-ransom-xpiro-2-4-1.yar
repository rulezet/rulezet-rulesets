rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "149fda05458720c56fe36871c2d8991a4f67ad87fb512873c6e7b481fca078c0"

  strings:
    $s1 = "LUsk%u=34" fullword ascii
    $s2 = "ColorP Document" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}