rule Trojan_Autorun_Trojan_GenericKDZ_72348_9 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.72348_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b8c6d879f0bb9c38fd9eaba7de2eff5b19f01efad4d3180291f8d5543f401a7"

  strings:
    $s1 = "acknowledge that you will create and activate an administrator account and password and that the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}