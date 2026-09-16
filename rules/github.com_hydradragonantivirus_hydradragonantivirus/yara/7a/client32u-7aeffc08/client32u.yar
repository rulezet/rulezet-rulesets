rule client32u {
  meta:
    description = "19438 - file client32u.ini"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
    date        = "2023-10-29"
    hash1       = "aa92645428fb4c4e2cccbdf9b6acd7e6a51eecc2d6d63d7b8fe2e119e93c2bb5"

  strings:
    $s1  = "ValidAddresses.TCP=*" fullword ascii
    $s2  = "Passwordu=" fullword ascii
    $s3  = "Filename=C:\\ProgramData\\SchCache\\client32u.ini" fullword ascii
    $s4  = "SecondaryPort=133" fullword ascii
    $s5  = "Port=133" fullword ascii
    $s6  = "UsernamesU=*" fullword ascii
    $s7  = "SecurityKeyU=dgAAABrz4TvGMrqEdp4jnSqauXAA" fullword ascii
    $s8  = "[HTTP]" fullword ascii
    $s9  = "Protocols=2,3" fullword ascii
    $s10 = "DisableChatMenu=1" fullword ascii
    $s11 = "SKMode=1" fullword ascii
    $s12 = "quiet=1" fullword ascii
    $s13 = "DisableRequestHelp=1" fullword ascii
    $s14 = "DisableChat=1" fullword ascii
    $s15 = "HideWhenIdle=1" fullword ascii
    $s16 = "DisableAudioFilter=1" fullword ascii
    $s17 = "SysTray=0" fullword ascii
    $s18 = "DisableReplayMenu=1" fullword ascii
    $s19 = "DisableDisconnect=1" fullword ascii
    $s20 = "[_License]" fullword ascii

  condition:
    uint16(0) == 0x7830 and filesize < 1KB and
    8 of them
}