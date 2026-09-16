rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_amBwvTb_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@amBwvTb_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54ba3497aec11f09d2223797527a5ef4bdf97014257ed445e35f3ed7dcaf84fe"

  strings:
    $s1 = "<N:nAst" fullword ascii
    $s2 = "FizZ&)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}