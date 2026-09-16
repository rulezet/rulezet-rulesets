rule Virus_Hijack_Trojan_GenericKDZ_105924_302_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_302_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31f693df719b2e6162cb4fe4c7e6b7d3d544a8ededef039fcd788f0537286b01"

  strings:
    $s1 = "u\"wAar" fullword ascii
    $s2 = "t`lOwY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}