rule VirusShareTrojanBtcMine1812 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanBtcMine1812.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23c30012cb4ba6b48e3582965f31508abe28cf2eaa76ba3fb877b635d2ed5b21"

  strings:
    $s1 = "Copyright 2017 Google Inc. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}