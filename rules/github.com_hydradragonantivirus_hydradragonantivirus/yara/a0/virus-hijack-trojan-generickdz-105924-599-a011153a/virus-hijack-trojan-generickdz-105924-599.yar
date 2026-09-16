rule Virus_Hijack_Trojan_GenericKDZ_105924_599 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_599.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82a26af7073faf50c28e165a7c5c99153bfb1e9f218a039e4f89e81213c4bf34"

  strings:
    $s1 = "tetH``" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}