rule Virus_Hijack_Trojan_GenericKDZ_98113_218_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_218_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64dabdc578d1214516e672230667c8416302585a4f7e62e2471ea0dea7098321"

  strings:
    $s1 = "foAL<Fe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}