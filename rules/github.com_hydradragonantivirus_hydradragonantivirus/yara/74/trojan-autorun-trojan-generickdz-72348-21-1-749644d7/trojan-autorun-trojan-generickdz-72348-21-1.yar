rule Trojan_Autorun_Trojan_GenericKDZ_72348_21_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.72348_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60a061bac71682ce4400251ce4bcee1fd9743a1575aa2808c26e0a38995d7ced"

  strings:
    $s1 = "!ZEBu[NBb\\Y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}