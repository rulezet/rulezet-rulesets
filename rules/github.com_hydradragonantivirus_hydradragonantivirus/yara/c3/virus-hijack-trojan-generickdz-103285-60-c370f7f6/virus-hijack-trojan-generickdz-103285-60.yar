rule Virus_Hijack_Trojan_GenericKDZ_103285_60 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_60.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94c80d53b4289ec92eab3b0cc10ce158ea2a972539fc2c4f099054ac19dcc026"

  strings:
    $s1 = "nWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}