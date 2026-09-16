rule Virus_Hijack_Trojan_GenericKDZ_103285_720 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_720.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e491a77d05f3e758d5acc89db471e0bc15350dca9fd0527764ed6544cf9a6b7"

  strings:
    $s1 = "Fdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}