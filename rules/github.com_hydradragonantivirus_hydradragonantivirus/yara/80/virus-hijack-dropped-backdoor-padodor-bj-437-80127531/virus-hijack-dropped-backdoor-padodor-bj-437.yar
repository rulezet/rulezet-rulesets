rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_437 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_437.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c705d027e23be9a4eae09db01a26bfa2d5d6167969ae6045d7bccec5143a3ff"

  strings:
    $s1 = "Fn*aFFy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}