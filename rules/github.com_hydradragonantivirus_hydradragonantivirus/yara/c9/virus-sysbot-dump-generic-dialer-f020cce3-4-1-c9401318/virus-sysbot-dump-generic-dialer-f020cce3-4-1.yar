rule Virus_Sysbot_Dump_Generic_Dialer_F020CCE3_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.F020CCE3_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfbfd832b9522cd4fa62b414dcce06fd6987127eb183e3b5213515128037d48c"

  strings:
    $s1 = "rORy#k" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}