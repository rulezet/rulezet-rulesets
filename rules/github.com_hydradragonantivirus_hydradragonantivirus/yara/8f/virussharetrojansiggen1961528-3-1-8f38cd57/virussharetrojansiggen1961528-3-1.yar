rule VirusShareTrojanSiggen1961528_3_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1961528_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b87e6905e6a2c6166fc3f7b84bde785a0914cb444814acd2a54ac433ae61db29"

  strings:
    $s1 = "  'description': 'A person'," fullword wide
    $s2 = "Autostart program viewer" fullword ascii
    $s3 = "(Copyright (C) 2002-2021 Mark Russinovich" fullword ascii
    $s4 = "Copyright (C) 2002-2021 Mark Russinovich" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}