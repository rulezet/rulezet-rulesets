rule Trojan_Danger_Trojan_GenericKD_67166905_170_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_170_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a548b1e78ce7b8a09032f6a0553442b74f667fd00a225075fd32082f062dab38"

  strings:
    $s1 = "?policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}