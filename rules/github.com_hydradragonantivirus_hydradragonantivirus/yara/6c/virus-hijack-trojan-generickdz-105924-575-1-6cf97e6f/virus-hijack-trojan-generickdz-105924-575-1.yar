rule Virus_Hijack_Trojan_GenericKDZ_105924_575_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_575_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64fa286333ee727513180ad0bdf34ba477f7741eed9d7d9b96983e5b89e07840"

  strings:
    $s1 = "A}cRoc" fullword ascii
    $s2 = "%Tory<k" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}