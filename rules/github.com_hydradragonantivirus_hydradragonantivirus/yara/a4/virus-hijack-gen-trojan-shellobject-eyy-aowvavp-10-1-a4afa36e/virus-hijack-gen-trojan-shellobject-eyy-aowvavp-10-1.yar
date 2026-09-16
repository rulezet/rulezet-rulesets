rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aOWVavp_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aOWVavp_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a56f581e5702649e6e049130a90f9beb954acc90fc5d060366cf4de35b493914"

  strings:
    $s1 = "T#veRy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}