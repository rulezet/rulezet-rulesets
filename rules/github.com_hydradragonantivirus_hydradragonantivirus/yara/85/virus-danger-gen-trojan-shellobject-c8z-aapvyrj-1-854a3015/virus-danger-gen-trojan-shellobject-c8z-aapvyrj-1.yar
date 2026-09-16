rule Virus_Danger_Gen_Trojan_ShellObject_C8Z_aaPVyRj_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.C8Z@aaPVyRj_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c216941d3dc78c9f3cc076e654deeadfae84cb74b2cc7b999000aba4c965c7aa"

  strings:
    $s1 = "Resource Monitor.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}