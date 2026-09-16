rule Virus_Hijack_Gen_Trojan_ShellObject_iCZ_am59Gmh_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iCZ@am59Gmh_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43db14f61cedb5d8d50e479192eb4b7edd8ab247afca5ca751605fdad51d3aba"

  strings:
    $s1 = "eF}taLD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}