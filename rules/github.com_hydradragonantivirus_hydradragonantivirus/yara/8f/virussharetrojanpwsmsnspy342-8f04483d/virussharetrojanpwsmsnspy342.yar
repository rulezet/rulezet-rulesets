rule VirusShareTrojanPWSMSNSpy342 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPWSMSNSpy342.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae11bcdc62b52362c0d848c5ad8fe50e0ec4b345f1c0c0fadabab04cdd9906b3"

  strings:
    $s1  = "start C:/high/file1.exe" fullword ascii
    $s2  = "start C:/high/file.exe" fullword ascii
    $s3  = "stealer@amnesia.com" fullword wide
    $s4  = "SELECT ProcessorId FROM Win32_Processor" fullword wide
    $s5  = "\\Documents\\Visual Studio 2012\\Projects\\Stealer\\Stealer\\obj\\Debug\\Stealer.pdb" fullword ascii
    $s6  = "log@domain:pass" fullword wide
    $s7  = "log:pass" fullword wide
    $s8  = "Stealer" fullword wide
    $s9  = "Cannot assign a %s to a %s*Can't write to a read-only resource stream%String list does not allow duplicates" fullword wide
    $s10 = " Yandex.ru v 2.7.5  [Cracked by RageGod]" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}