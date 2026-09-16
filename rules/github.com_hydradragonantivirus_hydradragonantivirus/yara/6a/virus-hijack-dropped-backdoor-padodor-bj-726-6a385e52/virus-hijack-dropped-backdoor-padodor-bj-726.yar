rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_726 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_726.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7391eac8f8c1b118f834a5e2e6f5cab637f4b8ac032d2363004bac89e8fedf2c"

  strings:
    $s1 = "Lmprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}