rule Trojan_Sysbot_Trojan_GenericKDZ_104643_58_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKDZ.104643_58_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49395ba61b12e217b3e17954ea534e6da2f139fdeb21726a159b17ad1d597998"

  strings:
    $s1 = "oUTfiT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}