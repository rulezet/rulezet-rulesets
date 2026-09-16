rule Trojan_Autorun_Generic_Dacic_06B5CF0E_A_DD3400CB_8_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.06B5CF0E.A.DD3400CB_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61473123725f95ccaa56d11020023d12bc1c35b8c96e04ca39a7ac80ebe12a90"

  strings:
    $s1 = "N}4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}