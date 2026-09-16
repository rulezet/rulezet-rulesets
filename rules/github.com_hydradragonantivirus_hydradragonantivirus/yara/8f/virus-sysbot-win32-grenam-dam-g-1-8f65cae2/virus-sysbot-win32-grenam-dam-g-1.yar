rule Virus_Sysbot_Win32_Grenam_Dam_G_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Win32.Grenam.Dam.G_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfb2f0f7123ee0f4ed44d7b4719e99d2a92f6b4bfde47b594b68362f872aaf0f"

  strings:
    $s1 = "Orientation,%B" fullword ascii
    $s2 = "Color@'B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}