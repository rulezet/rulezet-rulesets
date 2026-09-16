import "pe"
rule _VirusShareTrojanSiggen1961528_11_1_VirusShareTrojanSiggen196152_324 {
  meta:
    description = "datamaliciousorder - from files VirusShareTrojanSiggen1961528_11_1.vir, VirusShareTrojanSiggen1961528_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45e0b1690ae13ec10f9147ffdd9c2ab01fe1ae3c1aa52310d1adbf5116b474be"
    hash2       = "cc56d060f51bd70e91e49d146f4cdb9ea8310bf799fecea4f9274b61e525f953"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
    $s2  = "\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:" ascii
    $s3  = "Add \"Ru&n with graphics processor\" to Context Menu" fullword wide
    $s4  = "Exclude hidden files and directories" fullword wide
    $s5  = "System &Information" fullword wide
    $s6  = "Press 'Enter' key to perform a web search" fullword wide
    $s7  = "Bing Search" fullword wide
    $s8  = "Exclude system files and directories" fullword wide
    $s9  = "re=\"AMD64\" name=\"Microsoft.Windows.Sedona\" type=\"win32\"></assemblyIdentity><description>Your app description here</descrip" ascii
    $s10 = "Add Desktop Context &Menu" fullword wide
    $s11 = "Add \"&Render OpenGL on\" Option to Context Menu" fullword wide
    $s12 = "NVIDIA Control Panel &Help" fullword wide
    $s13 = "&About NVIDIA Control Panel" fullword wide
    $s14 = "Re&cent Tasks" fullword wide
    $s15 = "Re&lated Tasks" fullword wide
    $s16 = "Open to &Last Page Viewed" fullword wide
    $s17 = "&Surround Displays" fullword wide
    $s18 = "&Confine Taskbar to Center Display" fullword wide
    $s19 = "&Maximize Windows Across All Displays" fullword wide
    $s20 = "Enable &Video Editing Mode" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "4328f7206db519cd4e82283211d98e83" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}