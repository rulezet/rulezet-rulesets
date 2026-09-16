rule Virus_Hijack_Trojan_GenericKDZ_103285_298 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_298.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25590348ddcf57f2425fb61ab17c64a042efe73e148890cae1aa07ab7db36f93"

  strings:
    $s1 = "YComputer: is defined as the computer on which the programs are installed. A Computer license allows you to use the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}