rule Virus_Hijack_Trojan_GenericKDZ_98113_196_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_196_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25d4358066db62119a8222744df51c2ecbe5e6405eaaecb6f2a2220e5c698804"

  strings:
    $s1 = "BalD,J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}