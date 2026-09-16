rule _Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aqOJzSd_2_2_Virus_Sysbo_163 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_2_2.vir, Virus.Sysbot_Dropped.Generic.AutorunINF.Recex.1.1C7C33CC.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ddd2c9145afaab6ae9d694619759a4d6569ae9345c64061e81160a1d2b93def"
    hash2       = "6607cf792b083f99fa7addb8d9c6c261cf597297b4d3be2d99429de6d4d956d5"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
    $s2 = "Preference initialization failed" fullword ascii
    $s3 = "Failed to Start AcroBroker for SynchronizerPrefs" fullword ascii
    $s4 = "Copyright 1984-2008 Adobe Systems Incorporated and its licensors. All rights reserved." fullword wide
    $s5 = "Adobe Collaboration Synchronizer 9.0" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and all of them)
    ) or (all of them)
}