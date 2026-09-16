rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_71_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_71_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0774b260cfd79f8fe011cbb7915feb75d15aa5c5d75cd59fdbd71f9bd5cf4e64"

  strings:
    $s1 = "sUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}