rule _Virus_Danger_Win32_Worm_VB_NZQ_Virus_Danger_Win32_Worm_VB_NZQ_1_85 {
  meta:
    description = "datamaliciousorder - from files Virus.Danger_Win32.Worm.VB.NZQ.vir, Virus.Danger_Win32.Worm.VB.NZQ_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a98af24eb749b1f0e6f17e981cd17a811f23c14594d444c9f36dbb07eedf6606"
    hash2       = "86501b6f1f138531408efabe39c58b5c8e5f00c20916a0aa803ab7578d2d8c9d"
    hash3       = "88ccd59e3eade1dc55a06d47d019588ee825a5fe6d7ba193c29137fb1b632142"

  strings:
    $s1  = "CMD.EXE with the /F:ON or /F:OFF switch.  You can enable or disable" fullword wide
    $s2  = "completion for all invocations of CMD.EXE on a machine and/or user logon" fullword wide
    $s3  = "can enable or disable completion for all invocations of CMD.EXE on a" fullword wide
    $s4  = "If Command Extensions are enabled, and running on the Windows XP" fullword wide
    $s5  = "Starts a new instance of the Windows XP command interpreter" fullword wide
    $s6  = "under Windows XP, as command line editing is always enabled." fullword wide
    $s7  = "START [\"title\"] [/Dpath] [/I] [/MIN] [/MAX] [/SEPARATE | /SHARED]" fullword wide
    $s8  = "following REG_DWORD values in the registry using REGEDT32.EXE:" fullword wide
    $s9  = "the registry using REGEDT32.EXE:" fullword wide
    $s10 = "Displays the Windows XP version." fullword wide
    $s11 = "session by setting either or both of the following REG_DWORD values in" fullword wide
    $s12 = "enable or disable file name completion for a particular invocation of" fullword wide
    $s13 = "under Windows XP." fullword wide
    $s14 = "File and Directory name completion is NOT enabled by default.  You can" fullword wide
    $s15 = "  $V   Windows XP version number" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}