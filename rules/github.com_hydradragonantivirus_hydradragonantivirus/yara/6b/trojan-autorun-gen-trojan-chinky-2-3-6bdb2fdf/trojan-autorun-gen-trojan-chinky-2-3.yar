rule Trojan_Autorun_Gen_Trojan_Chinky_2_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Chinky.2_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "860ac535e97570ad4a81070accece618ec617b370045c7e60a4d5a70f1013e0c"

  strings:
    $s1 = "<functionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}