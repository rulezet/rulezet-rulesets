rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aOWVavp_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aOWVavp_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c954bfb172a3d928fa3ccbc9a376ca2e39203d15925be3f90d54e006e6737a0"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><t" ascii
    $s2 = "ttp://schemas.microsoft.com/SMI/2005/WindowsSettings\"><dpiAware>true</dpiAware></asmv3:windowsSettings></asmv3:application><ms_" ascii
    $s3 = " failed with Win32 error code " fullword ascii
    $s4 = "25f93a}\"></ms_compatibility:supportedOS></ms_compatibility:application></ms_compatibility:compatibility></assembly>PPADDINGXXPA" ascii
    $s5 = " 2000-2021 by LibreOffice contributors. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}