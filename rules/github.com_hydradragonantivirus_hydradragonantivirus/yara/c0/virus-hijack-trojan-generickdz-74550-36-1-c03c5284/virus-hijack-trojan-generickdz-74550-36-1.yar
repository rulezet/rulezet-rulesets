rule Virus_Hijack_Trojan_GenericKDZ_74550_36_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_36_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "620734304b6b7af5ce83a2ea9478c77e3b5ef3d72c8df77aada33bb4345bcaf5"

  strings:
    $s1 = "gAVe{&u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}