rule Virus_Hijack_Trojan_GenericKDZ_105924_552_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_552_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26dee9cb987414da08271575bdb6e9aa53bb6fb4c6ba802e68d1ff429f4f60a1"

  strings:
    $s1 = "K(sOKa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}