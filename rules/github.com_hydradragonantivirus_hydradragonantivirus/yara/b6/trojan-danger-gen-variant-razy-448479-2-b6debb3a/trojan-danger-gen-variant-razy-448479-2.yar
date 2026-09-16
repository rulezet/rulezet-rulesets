rule Trojan_Danger_Gen_Variant_Razy_448479_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Razy.448479_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6d4ecd1761607def21d3c08cb4ca9dac2296862c5e40ed211e05ccbb615d89c"

  strings:
    $s1 = "#University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}