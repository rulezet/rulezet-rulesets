rule Virus_Hijack_GenPack_Backdoor_Hangup_B_296 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_296.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5f74f1d0e9993e36607d3ae750a55aa92b3bb439865cf2721bb8ec2665f56fc"

  strings:
    $s1 = "Iyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}