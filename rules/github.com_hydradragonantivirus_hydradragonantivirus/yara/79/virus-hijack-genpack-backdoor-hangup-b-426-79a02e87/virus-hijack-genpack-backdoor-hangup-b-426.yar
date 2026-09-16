rule Virus_Hijack_GenPack_Backdoor_Hangup_B_426 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_426.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "685de16c142ddaf89700e520d21f475cc296b8905e0f2d50998c2ac364e60107"

  strings:
    $s1 = "Qand hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}