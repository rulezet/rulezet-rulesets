rule Virus_Hijack_Trojan_GenericKDZ_105924_491_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_491_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "736d879df51497a06275c65dbc8948e44cfc317cfe33ed7cabf10f6400bb2f0b"

  strings:
    $s1 = "[]tEfF`th" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}