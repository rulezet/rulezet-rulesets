rule Virus_Hijack_Gen_Trojan_ShellObject_i4Z_aqH1LVc {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i4Z@aqH1LVc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eddb77f7d145320eb246f16a6a8df0dc725ef77f1584c3eef9d392da9c182f9a"

  strings:
    $s1 = "SOul<;b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}