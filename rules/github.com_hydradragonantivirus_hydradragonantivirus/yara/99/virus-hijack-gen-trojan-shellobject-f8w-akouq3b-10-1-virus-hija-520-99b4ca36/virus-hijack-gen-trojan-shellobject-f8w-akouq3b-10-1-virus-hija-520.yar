rule _Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_10_1_Virus_Hija_520 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9dd481aae9a5d9bb4492b165f159bb9b6e7d7a9fc94fa24820790c8c1d87ee10"
    hash2       = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash3       = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"
    hash4       = "88161fa41e18f1d57a2848956c024bd4376d03ece61626be61b46da1c9cd0062"
    hash5       = "4a358cd38d34db61937690de1c080533535f35e44b7ccc50d5b07c5bc183a797"

  strings:
    $s1 = ".Incompatible Operating System" fullword wide
    $s2 = "ERROR: failed to install the .NET Framework, try installing .NET 4.5 or higher manually" fullword ascii
    $s3 = "ERROR: please re-run this installer as a normal user instead of \"Run as Administrator\"." fullword ascii
    $s4 = ".Failed to install the .NET Framework, try installing .NET 4.5 or higher manually" fullword wide
    $s5 = "ERROR: cannot install for all users when a VDI environment is not detected." fullword ascii
    $s6 = "Please re-run this installer as a normal user instead of \"Run as Administrator\"." fullword wide
    $s7 = "yCannot install for all users when a VDI environment is not detected." fullword wide
    $s8 = "ERROR: this program cannot run on Windows XP or before; it requires a later version of Windows." fullword ascii
    $s9 = "This program cannot run on Windows XP or before; it requires a later version of Windows." fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}