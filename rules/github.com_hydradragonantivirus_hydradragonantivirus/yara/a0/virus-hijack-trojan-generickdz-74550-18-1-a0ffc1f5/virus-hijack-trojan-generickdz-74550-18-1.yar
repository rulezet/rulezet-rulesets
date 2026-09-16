rule Virus_Hijack_Trojan_GenericKDZ_74550_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81a769588e3b72cc3b3b2dd9f0c2c70a5de8d42511173a6148f967ab2c4b62f0"

  strings:
    $s1 = "{DoZe$" fullword ascii
    $s2 = "<%jUju" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}