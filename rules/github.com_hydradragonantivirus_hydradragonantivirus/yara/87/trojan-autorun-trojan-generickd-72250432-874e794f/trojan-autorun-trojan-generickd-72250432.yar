rule Trojan_Autorun_Trojan_GenericKD_72250432 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72250432.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4ebd6060fd0256643106881fe15ac168f98ae9c949a144849e9a2807d0a12a0"

  strings:
    $s1 = "REFUSE" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}