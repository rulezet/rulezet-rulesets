rule Virus_Hijack_Trojan_GenericKDZ_105924_100 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_100.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c6e543c78be9f9612aaa32664bad6a39500dc89db0b18852a26268804a6160e"

  strings:
    $s1 = "%obAn%}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}