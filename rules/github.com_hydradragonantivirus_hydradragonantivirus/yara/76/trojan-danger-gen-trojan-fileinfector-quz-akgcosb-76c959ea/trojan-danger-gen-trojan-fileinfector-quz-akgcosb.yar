rule Trojan_Danger_Gen_Trojan_FileInfector_quZ_aKGCosb {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Trojan.FileInfector.quZ@aKGCosb.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e09d57b6ac2edb98fc8ff594efee0429a89b1caf85e988781c3153b3d0791ab2"

  strings:
    $s1  = "COM+[5:0:55]: Backup RegDB file to 'C:\\WINDOWS\\system32\\emptyregdb.dat'." fullword ascii
    $s2  = "COM+[4:15:23]: CLB file C:\\Windows\\Registration\\R000000000001.clb successfully copied to C:\\$WINDOWS.~BT\\Work\\MachineIndep" ascii
    $s3  = "COM+[4:44:23]: CLB file C:\\Windows\\Registration\\R000000000001.clb successfully copied to C:\\$WINDOWS.~BT\\Work\\MachineIndep" ascii
    $s4  = "COM+[5:0:54]: CLB file C:\\$WINDOWS.~BT\\Store\\MachineIndependent\\File\\srcworkingalias\\agentmgr\\CCSIAgent\\005ACB6B\\R00000" ascii
    $s5  = "COM+[5:0:56]: ComPlusSetRole: Role = Reader, UsersInRole = , RoleFlag = 0x100" fullword ascii
    $s6  = "COM+[5:0:54]: CLB file C:\\$WINDOWS.~BT\\Store\\MachineIndependent\\File\\srcworkingalias\\agentmgr\\CCSIAgent\\005ACB6B\\R00000" ascii
    $s7  = "COM+[5:0:55]: Memory usage for setup process..." fullword ascii
    $s8  = "COM+[5:0:55]: CComPlusCore::DeleteAppByName: Removing IIS Out-Of-Process Pooled Applications from the COM+ catalog" fullword ascii
    $s9  = "COM+[5:0:54]: Processing tidCOMSERVICES_ROLECONFIG table" fullword ascii
    $s10 = "COM+[5:0:54]: Processing tidCOMSERVICES_ROLEDEFINITION table" fullword ascii
    $s11 = "COM+[5:0:55]: CComPlusCore::DeleteAppByName: Removing IIS In-Process Applications from the COM+ catalog" fullword ascii
    $s12 = "COM+[5:0:54]: Processing tidCOMSERVICES_ROLESET table" fullword ascii
    $s13 = "COM+[5:0:54]: Processing tidCOMSERVICES_SERVICES table" fullword ascii
    $s14 = "COM+[5:0:54]: Memory usage for setup process..." fullword ascii
    $s15 = "COM+[5:0:54]: Processing TID_CUSTOMACTIVATOR table" fullword ascii
    $s16 = "COM+[5:0:54]: Processing TID_COMPUTERLIST table" fullword ascii
    $s17 = "COM+[5:0:55]: ComPlusSetRole: Role = Administrator, UsersInRole = , RoleFlag = 0x100" fullword ascii
    $s18 = "COM+[4:15:23]: CLB file C:\\Windows\\Registration\\R000000000001.clb successfully copied to C:\\$WINDOWS.~BT\\Work\\MachineIndep" ascii
    $s19 = "COM+[4:44:23]: CLB file C:\\Windows\\Registration\\R000000000001.clb successfully copied to C:\\$WINDOWS.~BT\\Work\\MachineIndep" ascii
    $s20 = "COM+[5:0:55]: CComPlusCore::DeleteAppByName: Removing .NET Utilities from the COM+ catalog" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}