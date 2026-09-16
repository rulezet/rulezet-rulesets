rule Virus_Hijack_Trojan_GenericKDZ_98388_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3967012164377c09e029a1f664210d4491da023b4eec56479046cf3b6b53b8d"

  strings:
    $s1 = "&LuRK)15qE}J;" fullword ascii
    $s2 = "P!sUNN" fullword ascii
    $s3 = "gAnE{r" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}