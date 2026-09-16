rule Virus_Sysbot_Win32_Mydoom_L_mm_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Win32.Mydoom.L@mm_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1876e1e401c0aa2e2cf01690ddf098922980ce3efd3efeba7f4e77e21e92c51"

  strings:
    $s1 = "f6g6<9>l8>o>DAFt@FwFLIN|HN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}