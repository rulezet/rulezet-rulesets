rule Trojan_Autorun_Generic_Dacic_06B5CF0E_A_DD3400CB_7_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.06B5CF0E.A.DD3400CB_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "157ccd952a5d8154d66c6a78fe055a2b52ae546752c12feeb0c754ca0bfd4979"

  strings:
    $s1 = "54. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}