rule Virus_Infector_Gen_Variant_Ransom_TeslaCrypt_89_3 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.89_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5329f6cc8658b8a70abeaac7fd21af7da45ff58905031d88eafff5f9512ebe8"

  strings:
    $s1 = "!This program cannot be rGXBCD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}