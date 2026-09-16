rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_360 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_360.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9124fc34b567f89a0e707801ecc02f8815737a572c7fa42b28151d6a6c699a97"

  strings:
    $s1 = "+are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}