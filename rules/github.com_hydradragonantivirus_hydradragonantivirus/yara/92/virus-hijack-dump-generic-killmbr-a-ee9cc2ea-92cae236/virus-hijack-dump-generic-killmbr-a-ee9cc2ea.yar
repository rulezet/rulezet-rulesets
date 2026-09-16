rule Virus_Hijack_Dump_Generic_KillMBR_A_EE9CC2EA {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dump.Generic.KillMBR.A.EE9CC2EA.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "995adf539a9940727829abeaedd85459c50d04c0afda3330e0fa0d4ea476736e"

  strings:
    $s1 = ",PLEx*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}