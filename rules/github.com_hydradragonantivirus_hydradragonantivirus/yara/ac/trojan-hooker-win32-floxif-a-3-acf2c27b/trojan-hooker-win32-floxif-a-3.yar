rule Trojan_Hooker_Win32_Floxif_A_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd759795f51d715a03be3c148c87e9e48e301cba1a53b557ed69ba3a037e1560"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xml" ascii
    $s3 = " Install System v2.46.5-Unicode</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivilege" ascii
    $s4 = "A build of the Portable by TryRooM Launcher" fullword wide
    $s5 = "HyperSnap 9 Portable" fullword wide
    $s6 = "Portable by TryRooM Launcher" fullword wide
    $s7 = "Portable by TryRooM" fullword wide
    $s8 = "Copyright Portable by TryRooM" fullword wide
    $s9 = "urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supported" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}