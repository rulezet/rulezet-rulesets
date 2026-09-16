rule Virus_Hijack_Gen_Trojan_ShellObject_DuZ_amBwvTb_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DuZ@amBwvTb_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ddeb0e117ee81081bed8576267895b35d6408438ad5c95d87c72727ebe18ee4"

  strings:
    $s1 = "$a>mOXA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}