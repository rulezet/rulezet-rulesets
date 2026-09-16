rule Virus_Hijack_Win32_Grenam_Dam_G_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Grenam.Dam.G_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c87f83889a636ee6efc1c21105ea63d1d8c6a650a25edadd04b153908bdb986f"

  strings:
    $s1 = "Orientation,%B" fullword ascii
    $s2 = "Color@'B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}