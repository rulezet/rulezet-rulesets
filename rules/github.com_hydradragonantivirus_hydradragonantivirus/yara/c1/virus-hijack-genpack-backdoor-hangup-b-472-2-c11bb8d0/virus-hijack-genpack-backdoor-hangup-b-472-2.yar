rule Virus_Hijack_GenPack_Backdoor_Hangup_B_472_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_472_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "862604861a5835d58d6861e3f592db56a3a341f6c5f37f9419ba3463603c5521"

  strings:
    $x1  = "Starting Autodesk IDSDK Server process (Version: %1 Config: %2 Elevated: %3 File: %4)" fullword ascii
    $s2  = "Failed to remove inter-process mutex" fullword ascii
    $s3  = "Failed to lock inter-process mutex " fullword ascii
    $s4  = "Failed second time to lock inter-process mutex in 10 secs" fullword ascii
    $s5  = "Quitting Autodesk SSO Server process (Version: %1 Config: %2 File: %3)" fullword ascii
    $s6  = "Removed inter-process mutex. Trying to lock again." fullword ascii
    $s7  = ".?AV?$_Ref_count@V?$scoped_lock@Vinterprocess_mutex@interprocess@boost@@@interprocess@boost@@@std@@" fullword ascii
    $s8  = "Locked inter-process mutex successfully" fullword ascii
    $s9  = ".?AV?$_Ref_count@Vnamed_mutex@interprocess@boost@@@std@@" fullword ascii
    $s10 = "Failed to get a valid cryptor to verify the signature of configuration file." fullword ascii
    $s11 = "?LogInfo@Logger@IDSDKLog@Autodesk@@QEAAXPEB_W@Z" fullword ascii
    $s12 = "?GetLogLevel@Logger@IDSDKLog@Autodesk@@QEBA?AW4LogLevel@23@XZ" fullword ascii
    $s13 = "?GetInstance@Logger@IDSDKLog@Autodesk@@SA?AV123@PEB_W@Z" fullword ascii
    $s14 = "Failed to open or create named_mutex %1%. Error: %2%: %3%" fullword ascii
    $s15 = "OAuth2Code signal %1% acknowledged by the receiver process" fullword ascii
    $s16 = "Sending oauth2 code signal to all %1% SSO server processes" fullword ascii
    $s17 = "Sending oauth2 code signal %1% to the SSO server process pid %2%" fullword ascii
    $s18 = "?LogError@Logger@IDSDKLog@Autodesk@@QEAAXPEB_W@Z" fullword ascii
    $s19 = ".?AV?$_Ref_count@Vshared_memory_object@interprocess@boost@@@std@@" fullword ascii
    $s20 = "Quit the other default AdskIdentityManager process" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}