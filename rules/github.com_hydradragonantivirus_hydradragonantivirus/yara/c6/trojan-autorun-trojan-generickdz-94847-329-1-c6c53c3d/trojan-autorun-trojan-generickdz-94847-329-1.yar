rule Trojan_Autorun_Trojan_GenericKDZ_94847_329_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_329_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "415fec2d1cd86cfe5a322353d1d25d3c170a044c233ff441b6c822ef00c2697c"

  strings:
    $s1 = "Multiple purchase lines may be created on either a requisition or purchase order or may be a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}