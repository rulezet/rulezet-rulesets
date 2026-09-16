rule Virus_Hijack_Trojan_GenericKDZ_79663_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e7832f5b6bb68aafa5a6db8984fe7730f6d94d0ba69fd5412d554f810201ceb"

  strings:
    $s1 = "K!MusK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}