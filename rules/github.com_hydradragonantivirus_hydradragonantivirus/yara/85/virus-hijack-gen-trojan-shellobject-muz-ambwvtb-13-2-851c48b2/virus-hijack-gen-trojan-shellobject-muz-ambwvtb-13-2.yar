rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2de48242bcf5c405f59997131e317cf22f1f258f5b05abfb7e99278d86cfcff"

  strings:
    $s1 = "p{croP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}