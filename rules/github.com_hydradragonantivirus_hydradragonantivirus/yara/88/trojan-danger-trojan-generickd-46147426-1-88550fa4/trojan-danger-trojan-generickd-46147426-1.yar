rule Trojan_Danger_Trojan_GenericKD_46147426_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.46147426_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15b615439f0bdf1da796f6cc13472f2ba52078c9b168b5ce756c576e25e9079f"

  strings:
    $s1 = "#Epolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}