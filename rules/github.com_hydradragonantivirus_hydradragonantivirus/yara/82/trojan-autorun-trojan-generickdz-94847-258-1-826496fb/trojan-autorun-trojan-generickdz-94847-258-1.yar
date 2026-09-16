rule Trojan_Autorun_Trojan_GenericKDZ_94847_258_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_258_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "709fd08a802950a36b9e959d38b83b06413cafda56b5862083b0348cff546e2b"

  strings:
    $s1 = "M>TrOg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}