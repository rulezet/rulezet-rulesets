rule Virus_Hijack_Trojan_GenericKDZ_105924_278_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_278_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d296786f3fd48ccfb8ad16fae8b3844630853cdc2b1921c86e3a163f5a4c0f7"

  strings:
    $s1 = "could not find entry point." fullword wide
    $s2 = "J%roid" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}