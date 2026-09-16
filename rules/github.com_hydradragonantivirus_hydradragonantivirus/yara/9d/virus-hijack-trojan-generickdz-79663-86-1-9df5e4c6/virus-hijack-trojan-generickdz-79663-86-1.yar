rule Virus_Hijack_Trojan_GenericKDZ_79663_86_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_86_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b02b56692b4df650b2b7341aa96733681db078957d7fe62d572ce4811d98954"

  strings:
    $s1 = "LOuD;>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}