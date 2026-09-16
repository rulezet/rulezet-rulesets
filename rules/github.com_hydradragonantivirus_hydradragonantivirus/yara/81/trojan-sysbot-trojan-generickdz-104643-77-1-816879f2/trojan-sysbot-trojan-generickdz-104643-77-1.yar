rule Trojan_Sysbot_Trojan_GenericKDZ_104643_77_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKDZ.104643_77_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b3488f392b928aa0f3388679bb661553656187f186d12969c44eefc78f4cfa5"

  strings:
    $s1 = "H?F@HATE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}