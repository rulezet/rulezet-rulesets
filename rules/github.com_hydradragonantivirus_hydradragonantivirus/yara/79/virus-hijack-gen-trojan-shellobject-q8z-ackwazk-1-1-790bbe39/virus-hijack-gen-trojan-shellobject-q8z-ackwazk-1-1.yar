rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aCkwazk_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f345fe1d7105da80909a7530ec892003fb10d7f909b949e3ab3fe961aff4a5a"

  strings:
    $s1 = "e<BatS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}