rule Trojan_Autorun_Gen_Variant_Barys_121928_5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.121928_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9107756ffa52fe9f7fb5625c869002b79f8ee75bfb57610889627cd87a6e8c4"

  strings:
    $s1 = "+0assets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}