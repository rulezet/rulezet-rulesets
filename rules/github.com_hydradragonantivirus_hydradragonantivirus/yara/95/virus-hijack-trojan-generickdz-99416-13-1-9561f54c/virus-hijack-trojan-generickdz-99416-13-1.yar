rule Virus_Hijack_Trojan_GenericKDZ_99416_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6139640fd56233d50e1a8a5554f7b8692fb158ccad9b00e57e5659f43e86c791"

  strings:
    $s1 = "doUp%!D" fullword ascii
    $s2 = "sHay,*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}