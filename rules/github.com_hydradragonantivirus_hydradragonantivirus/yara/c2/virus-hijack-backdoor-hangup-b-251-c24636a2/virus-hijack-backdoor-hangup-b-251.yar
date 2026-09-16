rule Virus_Hijack_Backdoor_Hangup_B_251 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_251.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca4c8ffa78b9cb9ff1cd11d1b38ddd3aecbb8794c9378ee5dc57f4632f052be7"

  strings:
    $s1 = "{counted as \"n\" processors. For the Healthcare Transaction Base program, only the processors on which Internet Application" fullword ascii
    $s2 = "student enrolled in your institution counts as 25% of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}