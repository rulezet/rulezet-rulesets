rule Virus_Autorun_Win32_Neshta_A_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39714174e2a6937c6363de98453ef1d90ffe2bf0179b6a172a530eac375c0bd7"

  strings:
    $s1 = "34}Python Manuals.lnk" fullword ascii
    $s2 = "H?F@HATE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}