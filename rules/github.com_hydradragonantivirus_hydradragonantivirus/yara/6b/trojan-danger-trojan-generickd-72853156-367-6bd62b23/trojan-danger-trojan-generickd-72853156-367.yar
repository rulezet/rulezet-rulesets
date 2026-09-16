rule Trojan_Danger_Trojan_GenericKD_72853156_367 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_367.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b73234bc68ef61fb19102b9eb660c2719e347de659807e00a3e5ff9194dc82cc"

  strings:
    $s1 = "TRap?<RRRRRRnS__R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}