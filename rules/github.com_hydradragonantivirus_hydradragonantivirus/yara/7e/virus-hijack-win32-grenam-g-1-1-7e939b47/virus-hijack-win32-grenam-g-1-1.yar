rule Virus_Hijack_Win32_Grenam_G_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Grenam.G_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b731156e360522800bf2753b9f5dfeb947f7eaf7547db99e1807310dffba1d9f"

  strings:
    $s1 = "{t\"%uAnG" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}