rule Virus_Sysbot_GenPack_Generic_Dacic_Emdup_A_34291B55_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_GenPack.Generic.Dacic.Emdup.A.34291B55_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "855afa100361c825b38b76b491cb41cff364931f6973346cb8a21f91ef231cfe"

  strings:
    $s1 = "lOSH@\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}