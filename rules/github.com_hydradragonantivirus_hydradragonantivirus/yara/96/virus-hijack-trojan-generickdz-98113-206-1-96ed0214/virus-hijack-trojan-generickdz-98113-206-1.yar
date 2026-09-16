rule Virus_Hijack_Trojan_GenericKDZ_98113_206_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_206_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0099ae5a976ad70a11ee25e5794376c68617553c970e3c09ef03e2f897cffc36"

  strings:
    $s1 = "CLoP{N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}