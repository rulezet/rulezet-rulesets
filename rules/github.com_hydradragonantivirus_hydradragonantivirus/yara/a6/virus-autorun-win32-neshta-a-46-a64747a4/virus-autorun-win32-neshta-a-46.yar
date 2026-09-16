rule Virus_Autorun_Win32_Neshta_A_46 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_46.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ee84843d06b05cc4f4d087f9ce5d17b24464ca425dd2992196ae087af69121d"

  strings:
    $x1  = "Swarm: 1c6229a3ba8c9a284184a15a301af71b009cfe46, announce request: {\"ContentId\":\"1c6229a3ba8c9a284184a15a301af71b009cfe46\"," wide
    $s2  = "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\ADDINS\\Microsoft Power Query for Excel Integrated" wide
    $s3  = "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\ADDINS\\Microsoft Power Query for Excel Integrated" wide
    $s4  = "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\ADDINS\\Microsoft Power Query for Excel Integrated" wide
    $s5  = "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\ADDINS\\Microsoft Power Query for Excel Integrated" wide
    $s6  = "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\ADDINS\\PowerPivot Excel Add-in\\pt\\Microsoft.Excel" wide
    $s7  = "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\ADDINS\\PowerPivot Excel Add-in\\pt\\Microsoft.Excel" wide
    $s8  = "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\ADDINS\\PowerPivot Excel Add-in\\pt\\Microsoft.Repor" wide
    $s9  = "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Office\\root\\Office16\\ADDINS\\Microsoft Power Query for Excel Integrated" wide
    $s10 = "Swarm: 66c5087841c222e59824711fb076fb5c9701b671, announce complete, event: 3, hr: 0, server: [51.104.167.186]:443 (https://array" wide
    $s11 = "Swarm: d45559e8240938d9509a38e4cfd42bdc916f57d0, announce complete, event: 3, hr: 0, server: [51.104.167.186]:443 (https://array" wide
    $s12 = "DownC:\\Program Files (x86)\\McAfee Security Scan\\4.1.491\\McCHSvc.exe" fullword wide
    $s13 = "C:\\Program Files (x86)\\McAfee Security Scan\\uninstallx.exe" fullword wide
    $s14 = "C:\\Program Files (x86)\\McAfee Security Scan\\4.1.482\\McCHSvc.exe" fullword wide
    $s15 = "C::Users:Luis Manuel:AppData:Local:Microsoft:Windows:Explorer:thumbcache_idx.db!rwReaderRefssl" fullword wide
    $s16 = "ROOT#SCANNER#0000#{6bdd1fc6-810f-11d0-bec7-08002be2092f}" fullword wide
    $s17 = "\\Program Files (x86)\\McAfee Security Scan" fullword wide
    $s18 = "\\Program Files (x86)\\McAfee Security Scan\\4.1.515wer" fullword wide
    $s19 = "McAfee Security Scan" fullword wide
    $s20 = "AtmA<I%r" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}