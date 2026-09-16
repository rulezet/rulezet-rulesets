rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "931623def679edfdb0216cae12b89343b53aec8bc4167e7129b39ad42b7b6b61"

  strings:
    $s1 = "iZAR(#I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}