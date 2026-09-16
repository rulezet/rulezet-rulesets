rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_156_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_156_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3834a31ddd8d234cd16a7743a156862928e8904692a36f0723e79ae3d563dde2"

  strings:
    $s1 = "oUProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}