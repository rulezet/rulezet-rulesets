rule Virus_Hijack_Trojan_GenericKDZ_94849_41_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_41_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b33b0c91e3ca42dee85fc2dfa18f86399647a2c7f9bd7f8016892a2ddf69271"

  strings:
    $s1 = "dazE0N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}