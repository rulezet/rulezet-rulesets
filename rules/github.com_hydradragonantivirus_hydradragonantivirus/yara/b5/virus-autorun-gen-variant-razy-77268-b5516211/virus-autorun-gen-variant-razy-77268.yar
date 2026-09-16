rule Virus_Autorun_Gen_Variant_Razy_77268 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Gen.Variant.Razy.77268.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62d93cc3c4cc8352c9c0d11c6d05d2973fc60246cb4dccccf3f0186df0b14929"

  strings:
    $s1 = "urva,B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}