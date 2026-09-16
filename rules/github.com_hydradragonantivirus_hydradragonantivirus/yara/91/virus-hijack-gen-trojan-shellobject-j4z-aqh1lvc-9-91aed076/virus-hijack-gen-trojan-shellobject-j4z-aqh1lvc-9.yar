rule Virus_Hijack_Gen_Trojan_ShellObject_j4Z_aqH1LVc_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28fa129ed54d9ae01fc4b231fe65aacb8b45b60f02d94fc5b53e9a1a86aa57e6"

  strings:
    $s1 = "8must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}