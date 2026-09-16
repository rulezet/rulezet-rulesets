rule Virus_Hijack_Win32_Worm_VB_AND_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Worm.VB.AND_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2570411b59a7120449af52495978b9e5b5a74648cb63d5805052765302d86947"

  strings:
    $s1 = "jElL$`U" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}