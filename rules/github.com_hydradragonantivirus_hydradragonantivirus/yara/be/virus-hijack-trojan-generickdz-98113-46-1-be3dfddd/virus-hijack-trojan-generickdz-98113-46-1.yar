rule Virus_Hijack_Trojan_GenericKDZ_98113_46_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_46_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf2c409e015da2949d5430f423f68bc8ae9c646dfea11761c22a52f17c1d6d48"

  strings:
    $s1 = "teaL*b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}