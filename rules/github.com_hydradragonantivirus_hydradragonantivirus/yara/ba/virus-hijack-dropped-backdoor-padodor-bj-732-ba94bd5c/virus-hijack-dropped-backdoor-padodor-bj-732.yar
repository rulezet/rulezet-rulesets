rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_732 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_732.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "524d43d2ba1c360bd02ffdaf23ce7f3543c33db872e89a4d8dfeebd38e0e433b"

  strings:
    $s1 = "(If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}