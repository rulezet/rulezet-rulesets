rule Virus_Hijack_Trojan_GenericKDZ_105924_508_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_508_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a182b7be03864c3b42c2b3ac412c74db24790cdd17189488517c7fd4435a1f4"

  strings:
    $s1 = "Q(coup" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}