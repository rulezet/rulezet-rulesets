rule Virus_Infector_Win32_Expiro_Gen_7_60 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_60.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83a58f530bf6398c6c96a62f46c2b936c4585e61c49a98552689123835648e3d"

  strings:
    $s1 = "q|T5i&oPAl" fullword ascii
    $s2 = ":TOle." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}