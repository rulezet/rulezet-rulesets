import "pe"
rule _Virus_Hijack_Trojan_Agent_DQQO_135_2_Virus_Hijack_Trojan_Agent__80 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.Agent.DQQO_135_2.vir, Virus.Hijack_Trojan.Agent.DQQO_142_2.vir, Virus.Hijack_Trojan.Agent.DQQO_143_2.vir, Virus.Hijack_Trojan.Agent.DQQO_144_2.vir, Virus.Hijack_Trojan.Agent.DQQO_145_2.vir, Virus.Infector_Win32.Sality.3_1.vir, Virus.Sysbot_Win32.Sality.3_1.vir, Virus.Sysbot_Win32.Sality.3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d05fee8d75278687330033ad56eb1f71eff4dfdf64e7179bd6986f249d70cb29"
    hash2       = "239b24446ca68987f67d94433f1feb32f5564be7fb7af70345dc664bce82fc10"
    hash3       = "af1c46316133ce5bf081f83688b7c68a12d83106388ef9422ac58e42715e78aa"
    hash4       = "141c0fd47fd45f574e7207ca8cf40caa4110d3aba70a385e714b5fb78f8a832d"
    hash5       = "f33f1e82233bb0f730eb60de37523446a2c60d3d27e26f98c9c4471aa15edeae"
    hash6       = "dad4d75714a417b1636757a2e32fef26a70aec0010db95e5c94ed9fbfbf42258"
    hash7       = "aa3e2dc6f999443198190093e87373a7898255898dd8bd343ceca61ae67600b5"
    hash8       = "69b3b28fd64f2c1e3f7b3070cd27c271e1e9662c9ae770bbb1bbf4cffa40ead5"

  strings:
    $x1  = "PA<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.48.05\" processor" ascii
    $s2  = "PA<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.48.05\" processor" ascii
    $s3  = "Could not open URL http://www.autohotkey.com in default browser." fullword ascii
    $s4  = "RunAs: Missing advapi32.dll.  The current thread will exit." fullword ascii
    $s5  = "command option was not enabled in the original script." fullword ascii
    $s6  = "CreateProcessWithLogonW.  The current thread will exit." fullword ascii
    $s7  = "{Blind}%s%s{%s DownTemp}" fullword ascii
    $s8  = "Script lines most recently executed (oldest first).  Press [F5] to refresh.  The seconds elapsed between a line and the one afte" ascii
    $s9  = "Script lines most recently executed (oldest first).  Press [F5] to refresh.  The seconds elapsed between a line and the one afte" ascii
    $s10 = "Target label does not exist.  The current thread will exit." fullword ascii
    $s11 = "The oldest are listed first.  VK=Virtual Key, SC=Scan Code, Elapsed=Seconds since the previous event.  Types: h=Hook Hotkey, s=S" ascii
    $s12 = "Compile error %d at offset %d: %s" fullword ascii
    $s13 = "Target label does not exist." fullword ascii
    $s14 = "r it is in parentheses to the right (if not 0).  The bottommost line's elapsed time is the number of seconds since it executed." fullword ascii
    $s15 = "Interrupted threads: %d%s" fullword ascii
    $s16 = "Failed attempt to launch program or document:" fullword ascii
    $s17 = "NOTE: Only the script's own keyboard events are shown" fullword ascii
    $s18 = ">AUTOHOTKEY SCRIPT<" fullword ascii
    $s19 = "Warning: The keyboard and/or mouse hook could not be activated; some parts of the script will not function." fullword ascii
    $s20 = "\"%s\" is not a valid key name.  The current thread will exit." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "376583ef03e4007760fb1259334fc710" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}