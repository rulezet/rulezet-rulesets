rule Virus_Hijack_Gen_Trojan_ShellObject_gyY_aWevApi_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyY@aWevApi_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56ef64b2a5790bf1722bcaad97208972c9eecd7a03ba6df0a74096be91b49610"

  strings:
    $s1 = ">?)TaPu" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}