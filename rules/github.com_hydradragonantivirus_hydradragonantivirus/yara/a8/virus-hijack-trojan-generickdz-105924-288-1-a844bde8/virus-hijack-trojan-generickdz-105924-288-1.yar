rule Virus_Hijack_Trojan_GenericKDZ_105924_288_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_288_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "297adeb170eb4982ebf8a200bac14fc8b5f06b24c091618f5da55af6d1b331eb"

  strings:
    $s1 = "$>baya" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}