rule Virus_Hijack_Trojan_GenericKDZ_105924_384_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_384_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f834e854b6a129a0a08344da49e947766879b2c74ae1130c75022a2749d561c4"

  strings:
    $s1 = "yS:cUVy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}