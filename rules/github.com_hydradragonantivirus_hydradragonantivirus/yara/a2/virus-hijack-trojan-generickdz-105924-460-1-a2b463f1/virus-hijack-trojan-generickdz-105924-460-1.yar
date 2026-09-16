rule Virus_Hijack_Trojan_GenericKDZ_105924_460_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_460_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecbc7c11ca563db600c8d31c46e0ea59287eb4edb2126dbd2a570ccbf3c84e85"

  strings:
    $s1 = "J`mixY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}