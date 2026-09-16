rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_24_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddc7a1c0e7a71a6054fa47b9a41ae64e82db5192129a3541dc70bc50b570a070"

  strings:
    $s1 = "Nwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}