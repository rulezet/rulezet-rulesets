rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "072c17ada13f484e6b0e8234fa14db1b73c5a99b9270d27214cf1332c4e88bf5"

  strings:
    $s1 = "LEAM}<_" fullword ascii
    $s2 = "VERd?>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}