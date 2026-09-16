rule Virus_Hijack_Trojan_GenericKDZ_99416_41 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_41.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72251bd83d4599205e7871ee1925ae07025de84b143cbd51b8de53939171ef1f"

  strings:
    $s1 = "]EUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}