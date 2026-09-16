rule Virus_Hijack_Trojan_GenericKDZ_105924_381_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_381_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a007b076daa24bce734180bba3369918c888dc7f128ee9755cbe77e74e255589"

  strings:
    $s1 = "ambA,L" fullword ascii
    $s2 = "GoGo`." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}