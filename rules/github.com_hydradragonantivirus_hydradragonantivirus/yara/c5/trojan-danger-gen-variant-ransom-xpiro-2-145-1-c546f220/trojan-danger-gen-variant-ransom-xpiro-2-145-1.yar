rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_145_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_145_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57705e6902d5d757d0b88b8a17bed3857e6fd3a003cf291dd27eaadca5ec73a6"

  strings:
    $s1 = "\"Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}