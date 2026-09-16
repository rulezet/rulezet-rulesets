rule Virus_Hijack_GenPack_Backdoor_Hangup_B_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5ef547ef8cae3236e67840af31b92be612fc3ce2b4df60de7b3a2e59d6b77a2"

  strings:
    $s1 = "the same degree of care to safeguard the confidentiality of the TRMs as you exercise to safeguard the confidenti`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}