rule Virus_Hijack_Gen_Trojan_ShellObject_CyZ_auPsdJb_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.CyZ@auPsdJb_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64fcb7f9f98df05ee0ebca88c584c9a440c94d421827ebcb9fae9ebdd9a1f9d8"

  strings:
    $s1 = "rEcCy?_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}