rule Virus_Sysbot_Gen_Heur_ManBat_1_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Heur.ManBat.1_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03dc5d716f004d1d2dcbf8c7ef65ea4b7f956c4c6dabe12476c43f77870da9cf"

  strings:
    $s1 = "SKAw<@w" fullword ascii
    $s2 = "smUt$R" fullword ascii
    $s3 = "W)JiNN" fullword ascii
    $s4 = "_;rami" fullword ascii
    $s5 = "g KZ\"ORdU" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}