rule Virus_Hijack_Backdoor_Hangup_B_307_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_307_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19ce3780b8c122e82c5183a04cdfdb1169b953477e069100df928a374692f6f0"

  strings:
    $s1 = "7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}