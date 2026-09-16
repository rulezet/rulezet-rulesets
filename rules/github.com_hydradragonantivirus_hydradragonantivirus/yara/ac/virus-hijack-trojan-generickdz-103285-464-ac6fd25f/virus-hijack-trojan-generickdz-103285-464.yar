rule Virus_Hijack_Trojan_GenericKDZ_103285_464 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_464.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46251cbba6fbf078699f0c60fbe62b3e1b2db0afffcf55ae69cfb9c6ab72324d"

  strings:
    $s1 = "J}SaIp" fullword ascii
    $s2 = "#\"SaIp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}