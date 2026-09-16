rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_18_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_18_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2645d35b050b69e2be28b55709d4049588ab55d1fe949aa1448378653452387"

  strings:
    $s1 = "@soft Visual Studio\\VB98;C:\\Windows\\system32;C:\\Windows\\system;C:\\Win" fullword wide
    $s2 = "|C:\\Program Files\\Microsoft Visual Studio\\VB98\\Wizards\\APPWIZ.oca" fullword ascii
    $s3 = "Color Demo" fullword ascii
    $s4 = "Wave Demo" fullword ascii
    $s5 = "Alpha Blend" fullword ascii
    $s6 = "Fast Mask" fullword ascii
    $s7 = "Color adjus." fullword ascii
    $s8 = "Demo Rotate" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}