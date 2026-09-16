rule Virus_Hijack_GenPack_Backdoor_Hangup_B_269 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_269.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb45bc26ca719336fea809fba7a55a4a360984dabb39045e2d04429c90a4630a"

  strings:
    $s1 = "tGcounted as \"n\" processors. For the Healthcare Transaction Base program, only the processors on which Internet Application" fullword ascii
    $s2 = "student enrolled in your institution counts as 25% of`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}