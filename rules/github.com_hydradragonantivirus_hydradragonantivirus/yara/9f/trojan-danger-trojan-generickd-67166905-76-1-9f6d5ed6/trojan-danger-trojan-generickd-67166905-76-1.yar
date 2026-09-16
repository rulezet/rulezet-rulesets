rule Trojan_Danger_Trojan_GenericKD_67166905_76_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_76_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c38d57f151c14a18e98cee9b9afc2469fdeb3e3e2598976598eaec537701c050"

  strings:
    $s1 = "Qpolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}