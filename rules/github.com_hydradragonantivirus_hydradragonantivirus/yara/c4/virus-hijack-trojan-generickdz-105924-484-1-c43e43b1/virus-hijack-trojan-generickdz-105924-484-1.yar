rule Virus_Hijack_Trojan_GenericKDZ_105924_484_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_484_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d112200e8f8b136c68107b7df13494bc06efd314ff80b9a8e3641fe2448db27"

  strings:
    $s1 = ";plan]" fullword ascii
    $s2 = "2<BoUT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}