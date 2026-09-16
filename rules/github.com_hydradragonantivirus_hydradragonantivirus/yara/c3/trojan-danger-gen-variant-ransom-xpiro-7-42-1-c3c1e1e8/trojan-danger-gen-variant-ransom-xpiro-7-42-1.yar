rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_42_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_42_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "411d3a03e0701be8a6c622924c17d9ba5c3ba34654a459e4b9e042e375aa74f8"

  strings:
    $s1 = "kvmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}