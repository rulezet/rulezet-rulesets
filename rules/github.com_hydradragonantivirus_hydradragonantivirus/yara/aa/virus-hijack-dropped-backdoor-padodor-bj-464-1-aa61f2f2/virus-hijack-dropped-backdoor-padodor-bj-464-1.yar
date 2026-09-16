rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_464_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_464_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67b9021d50b4bf7768d47fb20e2177bce38c9021b01b6253e9c8260be0e28a12"

  strings:
    $s1 = "2345 Protect Upgrade" fullword ascii
    $s2 = "Adobe Flash Update Task" fullword ascii
    $s3 = "Orientation$5B" fullword ascii
    $s4 = "This task keeps your Adobe Flash applications up to date with the latest enhancements and security fixes" fullword ascii
    $s5 = "Classes@ZA" fullword ascii
    $s6 = "Ins5Cannot create form. No MDI forms are currently active*A control cannot have itself as its parent" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}