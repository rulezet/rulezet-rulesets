rule Virus_Infector_Gen_Variant_Ransom_TeslaCrypt_89_5 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.89_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60c0f8954aca978a8c5f9873c2affc684d5029ff1d70e5a2b31e9da67349aaab"

  strings:
    $s1 = "!This program cannot be rGXBCD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}