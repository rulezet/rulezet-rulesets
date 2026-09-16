rule Virus_Hijack_GenPack_Backdoor_Hangup_B_176 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_176.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb38d74a6e8973e61bccaa72f19e48ff01983db9137fd14823140fb19701e7f2"

  strings:
    $s1 = "^Asoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}