rule Virus_Hijack_Trojan_GenericKDZ_105930_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7028216c7422463d40ecf2b895c5acf0819cdd08688dcfc1fcbac28ba2b85b85"

  strings:
    $s1 = "@]faCy" fullword ascii
    $s2 = "#NIck*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}