rule Trojan_Danger_Trojan_GenericKD_67166905_11_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dad0ade1dc73b0e762d1cbcd20d81663fa33162b3807a0bb446b81bd2b7c6267"

  strings:
    $s1 = "W@a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}