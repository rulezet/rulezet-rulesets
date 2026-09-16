rule Virus_Sysbot_GenPack_Generic_Dacic_Emdup_A_34291B55_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_GenPack.Generic.Dacic.Emdup.A.34291B55_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1009a65813a879a79a5e439d20c616b27a8f2d50da56fb5731d1d0b1cb198c28"

  strings:
    $s1 = "#NmJ;hIgH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}