rule Virus_Hijack_Backdoor_Hangup_B_30_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "075b92bd19016d7376cdaf330c474b0226936d6c0b94bcae26be88afb9e4c9bf"

  strings:
    $s1 = "7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}