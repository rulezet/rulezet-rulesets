rule VirusShareTrojanPacked243250_120_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPacked243250_120_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99be762e300ce54ae6afed2893d0906104a1765cca7bbbb2b9c20dcc99641819"

  strings:
    $s1 = "YAtE,E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}