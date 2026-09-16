rule Virus_Hijack_Trojan_GenericKDZ_98113_369_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_369_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1d9f55211f508cf3c8137725230839bfdf7bc713a3363d8613c6b7a118a31e5"

  strings:
    $s1 = "KiTE$Z" fullword ascii
    $s2 = "GOBy>u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}