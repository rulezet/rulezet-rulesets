rule Trojan_Autorun_Gen_Trojan_Heur_AutoIT_13_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Heur.AutoIT.13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db8199c7a17a9bd846b12446ac8a1fb3fd7aff331f10233b8d443ba43e6c379d"

  strings:
    $s1 = ",Vhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}