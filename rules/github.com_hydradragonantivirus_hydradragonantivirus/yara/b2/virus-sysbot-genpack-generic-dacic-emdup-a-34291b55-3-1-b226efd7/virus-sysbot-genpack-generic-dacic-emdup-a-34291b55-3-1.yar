rule Virus_Sysbot_GenPack_Generic_Dacic_Emdup_A_34291B55_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_GenPack.Generic.Dacic.Emdup.A.34291B55_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5ae86412aa06bd358538d25080bb2717318f737770926c73590c2fea54c0c55"

  strings:
    $s1 = "dUST<]" fullword ascii
    $s2 = "i%bolO:" fullword ascii
    $s3 = "}ColOr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}