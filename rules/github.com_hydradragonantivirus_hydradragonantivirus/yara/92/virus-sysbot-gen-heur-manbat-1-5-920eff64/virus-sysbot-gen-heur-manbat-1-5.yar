rule Virus_Sysbot_Gen_Heur_ManBat_1_5 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Heur.ManBat.1_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d59f6e56b1a779a8134ebc4b86f52b5828a01e147e9ab80d7c76f27fcb373cb"

  strings:
    $s1 = "pAtY;(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}