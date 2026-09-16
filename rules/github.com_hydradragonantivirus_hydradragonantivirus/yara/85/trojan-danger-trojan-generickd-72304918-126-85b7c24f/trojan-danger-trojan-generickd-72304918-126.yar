rule Trojan_Danger_Trojan_GenericKD_72304918_126 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_126.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1d740132283a96ca77b00ff66ee216d5203a049c17a360cbf8c991d4816a8b7"

  strings:
    $s1 = "TRap?<RRRRRRnS__R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}