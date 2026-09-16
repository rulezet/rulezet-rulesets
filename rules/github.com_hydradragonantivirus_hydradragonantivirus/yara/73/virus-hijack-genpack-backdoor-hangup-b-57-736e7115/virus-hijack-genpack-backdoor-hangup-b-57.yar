rule Virus_Hijack_GenPack_Backdoor_Hangup_B_57 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_57.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "782db2567e227a1ae41988903cfff4241a7aa5020faedca786a603b076d5f4cd"

  strings:
    $s1 = "T0and hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii
    $s2 = "%HATT>y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}