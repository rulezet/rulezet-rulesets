rule Virus_Hijack_Trojan_GenericKDZ_105924_412_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_412_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a475d8ac433351d061dfb87a0a2e0e014e2100b58eb9e8d963f3cd081359e4fc"

  strings:
    $s1 = "PAwL:<]DA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}