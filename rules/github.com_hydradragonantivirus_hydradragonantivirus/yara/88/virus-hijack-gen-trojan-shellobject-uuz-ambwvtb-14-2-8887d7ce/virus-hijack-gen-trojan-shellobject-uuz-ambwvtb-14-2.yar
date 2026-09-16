rule Virus_Hijack_Gen_Trojan_ShellObject_uuZ_amBwvTb_14_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uuZ@amBwvTb_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd188901444bcd2f1d47650f479e04c03a59166d884d64bb08e7409a5f60d423"

  strings:
    $s1 = "L;GAla" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}