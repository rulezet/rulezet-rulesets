rule Virus_Hijack_Trojan_GenericKDZ_105924_569_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_569_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab80b1214c4eefef447163100f71568b3b9eb7db52af7c0595f0385d3ce11743"

  strings:
    $s1 = ";gOGGa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}