rule Virus_Sysbot_Win32_Grenam_Dam_G {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Win32.Grenam.Dam.G.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0fbfc4c4fadebf05dd781327c662e7d272ff71d6db83932bddf5e46a43ed494"

  strings:
    $s1 = "Orientation,%B" fullword ascii
    $s2 = "Color@'B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}