rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_14_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa2a8caa4eaf1457c2b5d2580a0cd6b8afe307a5c5650b39e8fe7c1b57241279"

  strings:
    $s1 = "Office Telemetry Dashboard" fullword wide
    $s2 = "@{Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}