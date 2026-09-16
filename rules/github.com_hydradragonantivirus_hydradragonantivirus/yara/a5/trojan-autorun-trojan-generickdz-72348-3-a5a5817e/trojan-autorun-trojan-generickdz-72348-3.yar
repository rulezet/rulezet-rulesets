rule Trojan_Autorun_Trojan_GenericKDZ_72348_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.72348_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba1ac3400b37c29063937311e76ed03c3d73d0886aa61e9015a113b8a0db37e8"

  strings:
    $s1 = " license is the" fullword ascii
    $s2 = "Person: is defined as your employee or" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}