rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ac3b4bbc7a7ec90a477f68c2e1defabf6a0db36bb9a208e1d74333594f9b630"

  strings:
    $s1 = "g)d8>CLAt*" fullword ascii
    $s2 = "vota%[" fullword ascii
    $s3 = "3&uVaL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}