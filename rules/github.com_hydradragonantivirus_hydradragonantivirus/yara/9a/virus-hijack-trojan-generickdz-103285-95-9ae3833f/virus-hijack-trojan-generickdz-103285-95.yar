rule Virus_Hijack_Trojan_GenericKDZ_103285_95 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_95.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1d250cf7d73948ec6ca78b6246501d0309aedf5556f7acb6eb0aafe427bbf7b"

  strings:
    $s1 = "jRUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}