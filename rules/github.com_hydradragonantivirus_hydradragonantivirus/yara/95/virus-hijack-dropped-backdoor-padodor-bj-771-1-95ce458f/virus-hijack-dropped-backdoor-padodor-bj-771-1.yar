rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_771_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_771_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ec7dc3d1be623b5b0cc307020f4ade908f5f870406c3c56a0fe5b1b711624a8"

  strings:
    $s1 = "bolimba" fullword wide
    $s2 = "Mummied" fullword wide
    $s3 = "Overmourn" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}