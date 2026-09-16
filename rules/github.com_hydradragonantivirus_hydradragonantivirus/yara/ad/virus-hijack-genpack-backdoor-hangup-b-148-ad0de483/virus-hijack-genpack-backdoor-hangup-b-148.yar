rule Virus_Hijack_GenPack_Backdoor_Hangup_B_148 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_148.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d6b258b98740660d503e6c42616ba5253e12b4cd20d5ccce05415100c6a2df7"

  strings:
    $s1 = "XEyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}