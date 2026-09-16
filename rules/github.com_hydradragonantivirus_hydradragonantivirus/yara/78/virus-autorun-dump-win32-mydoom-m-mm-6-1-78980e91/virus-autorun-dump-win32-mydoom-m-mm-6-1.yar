rule Virus_Autorun_Dump_Win32_Mydoom_M_mm_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Win32.Mydoom.M@mm_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8de4f85a526244a2921b0e5af01d73aba7ea5b47f1007f4d14161f5ecfa9d5f4"

  strings:
    $s1 = "TRap?<RRRRn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}