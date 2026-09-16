rule Virus_Autorun_Gen_Variant_Doina_61378_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Gen.Variant.Doina.61378_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "722e9f91ab54ede4b8a1f2580d832fce640fff885104929580d0e5ca08ad1f28"

  strings:
    $s1 = "H?F@HATE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}