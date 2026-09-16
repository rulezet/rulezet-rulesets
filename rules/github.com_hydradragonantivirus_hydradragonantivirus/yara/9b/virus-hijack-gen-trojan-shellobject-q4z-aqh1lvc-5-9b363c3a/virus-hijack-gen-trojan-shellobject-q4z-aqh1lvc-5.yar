rule Virus_Hijack_Gen_Trojan_ShellObject_q4Z_aqH1LVc_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q4Z@aqH1LVc_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d50c512136675a9fd6e61261c42113217f60dd954f351c22d89ee6fd4bd1b8c"

  strings:
    $s1 = "MoIO,_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}