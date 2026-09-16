rule Trojan_Danger_Trojan_GenericKD_72304918_134_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_134_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9ac96e413dfe6b6e9de0b887a79540a430034d017eaecc3f887392e565a5886"

  strings:
    $s1 = "that you may receive from Microsoft during that year are also covered, but only for`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}