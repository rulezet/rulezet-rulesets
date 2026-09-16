rule Virus_Autorun_Win32_Neshta_A_2 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3b9d21d8fccd4d5bc0fdef8aff6f63e0c3713ed6f98503e854daec79e1eeb8a"

  strings:
    $s1 = "mfesec instance" fullword wide
    $s2 = "McAfee Filter Driver" fullword wide
    $s3 = "McAfee Windows Protection Suite" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}