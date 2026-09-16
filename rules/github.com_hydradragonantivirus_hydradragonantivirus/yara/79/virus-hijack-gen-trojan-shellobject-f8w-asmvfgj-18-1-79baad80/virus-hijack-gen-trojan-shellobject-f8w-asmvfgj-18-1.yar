rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSmvFGj_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSmvFGj_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4817e8fd7ab9ee5e5c61df653805d1f3164a732e3267c505d1afcbaa69b0ff39"

  strings:
    $s1 = "Push to exit" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}