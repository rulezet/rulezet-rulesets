rule Virus_Hijack_Trojan_GenericKDZ_105924_608_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_608_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84f655baa6b77c9f80d10e5886334b7a836e73ebd4469dd74549b47048a13b50"

  strings:
    $s1 = "{GOSh}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}