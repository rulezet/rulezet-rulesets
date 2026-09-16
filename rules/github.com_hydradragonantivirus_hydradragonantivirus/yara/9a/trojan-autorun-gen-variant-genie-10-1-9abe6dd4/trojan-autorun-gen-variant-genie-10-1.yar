rule Trojan_Autorun_Gen_Variant_Genie_10_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Genie.10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7de92feff5502e8e5b052e207ce27bcecfe01ba2b2434bfc2933b3d244924490"

  strings:
    $s1 = "Fhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}