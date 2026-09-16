rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_663 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_663.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb02de510cbd9035b59f7c37341246cd8cf54d1ab1f7a0324cf2e727dae0885f"

  strings:
    $s1 = ")Resource instance not specified, did you call CommonLibraryDllProcessAttach?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}