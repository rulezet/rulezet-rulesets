rule Virus_Infector_Win32_Sality_3_3 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Sality.3_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a5dc0a7c41ac359f33687944f06f997a9b306e077882afd440ea3a2598fc04c"

  strings:
    $s1 = "For the security of Windows NT servies. An important System service, If it was terminated, Windows would be Collapsed." fullword ascii
    $s2 = "Windows NT Service" fullword ascii
    $s3 = "Couldn't create service" fullword ascii
    $s4 = "coun't start service" fullword ascii
    $s5 = "Couldn't open service manager" fullword ascii
    $s6 = "Couldn't open service" fullword ascii
    $s7 = "explorer %s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}