rule Virus_Hooker_Win32_Ramnit_N {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Win32.Ramnit.N.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf4c98b5a1c9ebe7db1546e04e6d0d11e026aaf090ac7c9cb706fba50fd761c0"

  strings:
    $s1 = "Macromedia Flash Player 7.0" fullword wide
    $s2 = "Macromedia Flash Player" fullword wide
    $s3 = "Macromedia Flash Player 7.0  r19" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}