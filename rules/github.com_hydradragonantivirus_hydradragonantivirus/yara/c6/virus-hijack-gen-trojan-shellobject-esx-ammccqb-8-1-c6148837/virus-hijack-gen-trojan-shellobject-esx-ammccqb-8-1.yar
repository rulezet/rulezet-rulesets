rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c0ccf0e824f99edd28a677508184b582e44ab129a856e7a487b4f131463ab5e"

  strings:
    $x1  = "Error: NULL pointer passed to function ExecuteCommandSynchronous" fullword wide
    $s2  = "%s %s:  Failed to verify if the system is a Media Center machine Media Center machine: MCPreIns.exe won't execute on that machin" wide
    $s3  = "Warning: Failed to create command line process\"%s\"!  " fullword wide
    $s4  = "Error: Failed to execute commandline  '%s' (return value: 0x%08x)." fullword wide
    $s5  = "%s %s:  This is not a Media Center machine: MCPreIns.exe won't execute on that machine" fullword wide
    $s6  = "The version of '%s' indicates that this is a Freestyle/Lawndart machine - Continue execution" fullword wide
    $s7  = "Warning: Process Return Value is 0x%08x --> %s" fullword wide
    $s8  = "Warning: Couldn't get process Return Value. (0x%08x)." fullword wide
    $s9  = "This is a Media Center machine: MCPreIns.exe will execute on that machine" fullword wide
    $s10 = "Unable to identify target of '%s'" fullword wide
    $s11 = "Executing line \"%s\"" fullword wide
    $s12 = "Choose Cancel to continue using both formats. Choose Cancel if you still log on to Windows NT computers that are running version" wide
    $s13 = "7Access to the specified device, path or file is denied.9An error occurred sending the command to the application.1Extremely Low" wide
    $s14 = "Processing File: '%s'" fullword wide
    $s15 = "This registry indicates that this is a Freestyle/Lawndart machine - Continue execution" fullword wide
    $s16 = "Choose OK to delete the Windows NT version 3.1 program groups. If you choose OK, when you use a computer running Windows NT vers" wide
    $s17 = "An error occured during the execution of MCPreIns Code" fullword wide
    $s18 = " + mThe program group has been modified by another program or user and will be reloaded; try the operation again." fullword wide
    $s19 = "Error: failed to get arguments from command line: 0x%08x" fullword wide
    $s20 = "Parsing command line '%s'" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}