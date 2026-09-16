rule Virus_Autorun_Gen_Variant_Adware_MultiPlug_32 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Gen.Variant.Adware.MultiPlug.32.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e1454295a9101b6ee6d4191bf0ba7abbd7e0f7f0e7258adb0381101a663b974"

  strings:
    $s1 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"   /></requestedPrivileges></security></trustInfo><compatibility " ascii
    $s2 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"   /></requestedPrivileges></security></trustInfo><compatibility " ascii
    $s3 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
    $s4 = "s=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"  /><sup" ascii
    $s5 = "{fuTE`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}