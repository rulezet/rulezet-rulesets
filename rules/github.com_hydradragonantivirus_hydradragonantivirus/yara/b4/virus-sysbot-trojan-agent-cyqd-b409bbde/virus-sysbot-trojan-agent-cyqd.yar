rule Virus_Sysbot_Trojan_Agent_CYQD {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.Agent.CYQD.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdf25c48428cbcef760689901b503e1187cb48565e15b479067a9cd3c4b9fd17"

  strings:
    $x1  = "%s\\cmd.exe /c net user guest /active" fullword ascii
    $s2  = "GetSecurityDescriptorDacl() failed. Error %d" fullword ascii
    $s3  = "LookupAccountName() failed. Error %d" fullword ascii
    $s4  = "SetSecurityDescriptorDacl() failed. Error %d" fullword ascii
    $s5  = "Mozilla/4.0 (compatible; )" fullword ascii
    $s6  = "GetAclInformation() failed. Error %d" fullword ascii
    $s7  = "GetFileSecurity() failed. Error %d" fullword ascii
    $s8  = "GetAce() failed. Error %d" fullword ascii
    $s9  = "SetFileSecurity() failed. Error %d" fullword ascii
    $s10 = "AddAce() failed. Error %d" fullword ascii
    $s11 = "InitializeAcl() failed. Error %d" fullword ascii
    $s12 = "EnumResNameProc::FindResource ERROR!!CODE" fullword ascii
    $s13 = "AddAccessAllowedAce() failed. Error %d" fullword ascii
    $s14 = "HeapAlloc() failed. Error %d" fullword ascii
    $s15 = "AddAccessAllowedAceEx() failed. Error %d" fullword ascii
    $s16 = "additional header failed..." fullword ascii
    $s17 = "connection failed..." fullword ascii
    $s18 = "\\HTML Help Workshop\\" fullword ascii
    $s19 = "open internet failed..." fullword ascii
    $s20 = "response failed..." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}