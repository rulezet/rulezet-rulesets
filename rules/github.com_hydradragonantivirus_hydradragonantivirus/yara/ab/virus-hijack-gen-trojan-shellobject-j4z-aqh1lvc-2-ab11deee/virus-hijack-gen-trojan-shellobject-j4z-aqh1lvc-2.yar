rule Virus_Hijack_Gen_Trojan_ShellObject_j4Z_aqH1LVc_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e27a3e787a0b4796207879fccaa908817d56efdfc02f09a24815de9ab6dd61d"

  strings:
    $s1 = "<must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}