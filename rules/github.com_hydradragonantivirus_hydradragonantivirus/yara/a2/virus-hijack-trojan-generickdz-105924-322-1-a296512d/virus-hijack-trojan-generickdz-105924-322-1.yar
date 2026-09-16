rule Virus_Hijack_Trojan_GenericKDZ_105924_322_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_322_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c29bf053baca27ce94c351661e0768a8f81c777bdac1249ac36c3183618545f8"

  strings:
    $s1 = "uRge%x" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}