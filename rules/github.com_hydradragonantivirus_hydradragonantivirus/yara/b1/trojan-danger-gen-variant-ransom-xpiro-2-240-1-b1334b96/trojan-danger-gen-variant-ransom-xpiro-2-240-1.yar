rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_240_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_240_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6277608fbd8c364ce12bde4fdd063d413db7c8309dcdfb0e827b69e1cfd303b"

  strings:
    $s1 = "/Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}