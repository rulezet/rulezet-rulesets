rule Virus_Hijack_Trojan_GenericKDZ_105924_431_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_431_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7e1bcde965146bf469d61365c59ce63ade9089884483f581ff152e5cf12ca0d"

  strings:
    $s1 = "z`Jack" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}