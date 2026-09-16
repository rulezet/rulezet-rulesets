rule Virus_Sysbot_Win32_Virtob_Gen_12 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Win32.Virtob.Gen.12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b224d49e6ad9935b4d9779ecd785cddf035f266c9d1a0e1800ace504a58f304"

  strings:
    $s1 = "\\Usb 2.0 Driver" fullword wide
    $s2 = "Usb 2.0 Driver" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}