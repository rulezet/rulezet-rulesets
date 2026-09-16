rule Virus_Sysbot_Generic_Sdbot_7021C09F_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Generic.Sdbot.7021C09F_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84a24451c31bc6964af7a8f3bdb1c915c8bb555cdea7d4d794b3cb4b8516c26b"

  strings:
    $s1 = "b)DELF" fullword ascii
    $s2 = "=<zemNi" fullword ascii
    $s3 = "f%ADAY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}