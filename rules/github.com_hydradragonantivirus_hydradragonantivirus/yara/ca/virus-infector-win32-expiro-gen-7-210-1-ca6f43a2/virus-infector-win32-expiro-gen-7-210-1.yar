rule Virus_Infector_Win32_Expiro_Gen_7_210_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_210_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeacb5a736ebb9feacbace0c0ff7311b926a8f84b194659d0122cad6dc2762ff"

  strings:
    $s1 = "Proxifier Portable Edition v3.15" fullword wide
    $s2 = "Proxifier Portable Edition" fullword wide
    $s3 = " 2003-2012 Initex. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}