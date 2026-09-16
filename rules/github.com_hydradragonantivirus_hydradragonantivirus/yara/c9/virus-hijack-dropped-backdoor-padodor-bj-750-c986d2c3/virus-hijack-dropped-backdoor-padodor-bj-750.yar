rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_750 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_750.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bb01fa0303953c74236512dc65ec2ef9ee8940fbbaef5e6ea13fb93b3b2ae43"

  strings:
    $s1 = "VPYou may temporarily download the fonts to a prin" fullword ascii
    $s2 = "(including your list of `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}