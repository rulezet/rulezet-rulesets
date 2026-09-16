rule Virus_Hijack_Trojan_GenericKDZ_103285_139 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_139.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "403e29585a9fb02a7c14e93c611608a7465ae54ec9fec68ba0410e786230d25e"

  strings:
    $s1 = "lmicrosoft.com/office/backup. You may not distribute the backup copy of the software. You may use it" fullword ascii
    $s2 = "THOUGH WE DO NOT, YOU CA NNOT RECOVER MORE THA N YOU PAI`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}