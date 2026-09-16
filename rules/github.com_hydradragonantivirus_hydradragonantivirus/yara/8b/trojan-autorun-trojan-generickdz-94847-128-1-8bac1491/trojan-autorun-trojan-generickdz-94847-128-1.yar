rule Trojan_Autorun_Trojan_GenericKDZ_94847_128_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_128_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e71477e4224cfaccf7f00b3693710993cb0e75c76a35bf4a8aca5a4c707a0002"

  strings:
    $s1 = "Multiple purchase lines may be created on either a requisition or purchase order or may be a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}