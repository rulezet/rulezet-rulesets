rule Virus_Hijack_Trojan_GenericKDZ_103285_527 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_527.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d13df6d41d3b97c7970a0a68fa6628e172035d7013dbd44c78c77dd62c624b02"

  strings:
    $s1 = "AedN@etNA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}