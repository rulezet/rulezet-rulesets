rule Trojan_Autorun_Generic_Dacic_06B5CF0E_A_DD3400CB_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.06B5CF0E.A.DD3400CB_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8acea265eb9289b96eda3f607d8a74676ff3943fff10391292d7a2b2d7f19517"

  strings:
    $s1 = "ihundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}