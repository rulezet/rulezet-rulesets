rule VirusShareTrojanSiggen1526220_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1526220_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1cfa869ed35052bd7aa2895f764b31ac01e27d40ba08275db833f51a927dcbb"

  strings:
    $s1 = "E:\\Testing API\\Screen Working\\ScreenCapture 4.5\\Screen Working Updated\\ScreenCapture\\ScreenCapture\\obj\\Debug\\WindowHost" ascii
    $s2 = "E:\\Testing API\\Screen Working\\ScreenCapture 4.5\\Screen Working Updated\\ScreenCapture\\ScreenCapture\\obj\\Debug\\WindowHost" ascii
    $s3 = "Hello!@56&TempInfo" fullword wide
    $s4 = "Microsoft Host Service" fullword wide
    $s5 = "Error Occur : " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}