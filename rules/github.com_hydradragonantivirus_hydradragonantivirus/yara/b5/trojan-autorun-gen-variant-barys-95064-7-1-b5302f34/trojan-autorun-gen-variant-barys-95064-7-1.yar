rule Trojan_Autorun_Gen_Variant_Barys_95064_7_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.95064_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f61bacf752797a15065ee643626d4ef2dc94d3061c04c589fd006a763587040"

  strings:
    $s1 = "ws4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}