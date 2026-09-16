rule Trojan_Autorun_Trojan_GenericKDZ_94847_299_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_299_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "932336d193c34e79e578973b4051c1a2581bd197dc9e74b5ac5e87d97c5e2f90"

  strings:
    $s1 = "Owhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}