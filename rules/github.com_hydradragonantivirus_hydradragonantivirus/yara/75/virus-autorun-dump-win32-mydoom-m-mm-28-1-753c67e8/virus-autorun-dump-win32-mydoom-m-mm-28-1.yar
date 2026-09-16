rule Virus_Autorun_Dump_Win32_Mydoom_M_mm_28_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Win32.Mydoom.M@mm_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f793f45cb93eb8cd8c35b21d95f5bbd9feb5d9f20b39b2974f69f2972f53ec57"

  strings:
    $s1 = "Microsoft Office Publisher 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}