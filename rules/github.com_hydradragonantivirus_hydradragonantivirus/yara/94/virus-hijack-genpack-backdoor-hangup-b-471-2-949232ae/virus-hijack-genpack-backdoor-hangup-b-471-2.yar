rule Virus_Hijack_GenPack_Backdoor_Hangup_B_471_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_471_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8d50019e3d7943a4f9ab270b2d8091fd9e667a2be22a0d42e0c67ea0b6bba72"

  strings:
    $x1  = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii
    $s2  = "ns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"requireAdministrator\" u" ascii
    $s3  = "ess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-" ascii
    $s4  = "boot*.dll*" fullword wide
    $s5  = "expand \"%s\" -F:* \"%s\\\"" fullword wide
    $s6  = "\\Documents\\Visual Studio 2015\\Projects\\Dism++\\Release\\Dism++x64.pdb" fullword ascii
    $s7  = "expand \"%s\" -F:*.cix.xml \"%s\\\"" fullword wide
    $s8  = "Dism++ Version: %hu.%hu.%hu.%hu" fullword wide
    $s9  = "Dism++ Crash Auto Report-" fullword wide
    $s10 = "upd:Description" fullword ascii
    $s11 = "C Script " fullword wide
    $s12 = " /f BIOS" fullword wide
    $s13 = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword wide
    $s14 = " %s  Code 0x%.8X" fullword wide
    $s15 = "Dism++ Crash when UTC Time " fullword wide
    $s16 = "%Root%" fullword wide
    $s17 = "Range: bytes=%I64d-%I64d" fullword wide
    $s18 = "mar:Component" fullword ascii
    $s19 = "UnCompact;WofXpress4k;WofXpress8k;WofXpress16k;WofLZX" fullword wide
    $s20 = "WofAdk Mini-Filter Driver" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}