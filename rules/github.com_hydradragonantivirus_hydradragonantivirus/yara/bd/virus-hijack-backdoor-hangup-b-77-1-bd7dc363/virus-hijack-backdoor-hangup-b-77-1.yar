rule Virus_Hijack_Backdoor_Hangup_B_77_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_77_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d90b98830b69517dfb6885babadb92e9b2888644142e3c6820d21aed2edd39b"

  strings:
    $s1 = "(char)('" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}