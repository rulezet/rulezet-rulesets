rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aag1Gcl_24_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aag1Gcl_24_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3d380417ff300e5ca62e16e77b3977233df145e8c429a3bbb60eea59e3599b9"

  strings:
    $s1 = "?$SifT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}