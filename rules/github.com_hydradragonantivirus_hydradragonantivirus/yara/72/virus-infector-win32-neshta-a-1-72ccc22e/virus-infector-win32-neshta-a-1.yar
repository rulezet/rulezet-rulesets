rule Virus_Infector_Win32_Neshta_A_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Neshta.A_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e389c199195b38fd0ba9b9fe806e6fb1b5a76ec2291d3dadfd13384ee058d4e2"

  strings:
    $s1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
    $s2  = "*** Another PackageRemover instance is running ***" fullword wide
    $s3  = "Parent process is existing, wait for quit" fullword wide
    $s4  = "@[Enter] FindProcessID" fullword wide
    $s5  = "The process found" fullword wide
    $s6  = "[Leave] FindProcessID" fullword wide
    $s7  = "*** PackageRemover Start ***" fullword wide
    $s8  = "[PkgRemover] invalid command" fullword wide
    $s9  = "Build 1121 - None" fullword wide
    $s10 = ".?AVRegException@Storage@TmCommon@@" fullword ascii
    $s11 = ".PAVRegException@Storage@TmCommon@@" fullword ascii
    $s12 = "vileges></security></trustInfo><ms_compatibility:compatibility xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility." ascii
    $s13 = "[PkgRemover] unable to read INI file" fullword wide
    $s14 = "RemoveDirectory failed with error code %d" fullword wide
    $s15 = "1\"><ms_compatibility:application><ms_compatibility:supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"></ms_compatibility" ascii
    $s16 = "try to remove upper layer" fullword wide
    $s17 = "Trend Micro, Inc.1" fullword ascii
    $s18 = "[PkgRemover] the package is not extracted from self-extract" fullword wide
    $s19 = "Change Current Directory to " fullword wide
    $s20 = "Find PID of " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}