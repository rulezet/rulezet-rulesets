rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_325 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_325.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d21e704d10a06bd06ab1e62f0a82da52ee49ccf3d0ba400481be07b542ae700a"

  strings:
    $s1  = "LQyHpLaTpLvnz@FulL{f" fullword ascii
    $s2  = "Maun:.sDo`xD~`0W`.wKqdf" fullword ascii
    $s3  = "Maun:.x@ai" fullword ascii
    $s4  = "Maun:.uDcj" fullword ascii
    $s5  = "Maun:.yJye{Kf`pA;sk" fullword ascii
    $s6  = "Maun:.nWzlq" fullword ascii
    $s7  = "Maun:.jWzk" fullword ascii
    $s8  = "Maun:.}W`uqU;sk" fullword ascii
    $s9  = "Maun:.fRts{" fullword ascii
    $s10 = "Maun:." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}