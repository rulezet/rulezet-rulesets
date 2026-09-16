rule Trojan_Danger_Trojan_GenericKD_67166905_30_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58af5b22cad428dcfadecf8ebca84b509d3f2829f7722d7c93d666cf2389e98a"

  strings:
    $s1 = "{What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii
    $s2 = "adaw#d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}