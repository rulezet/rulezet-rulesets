rule Trojan_Autorun_Trojan_GenericKD_72517131_30_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fa5799f746e6401c91cd442bdf52921d05e6133cb9c11c6cfa84c957cf31974"

  strings:
    $s1 = "44. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}