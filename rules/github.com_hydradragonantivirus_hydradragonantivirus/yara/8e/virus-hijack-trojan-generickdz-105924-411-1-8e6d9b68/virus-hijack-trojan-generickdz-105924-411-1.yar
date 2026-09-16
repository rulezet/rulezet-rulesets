rule Virus_Hijack_Trojan_GenericKDZ_105924_411_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_411_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0835aa92ae0d7578409f078853793499c69f2035cf6b3a9e93f6dc9e84102ed"

  strings:
    $s1 = "leUK%Fc" fullword ascii
    $s2 = "Derm;(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}