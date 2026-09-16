rule Virus_Hijack_Gen_Trojan_ShellObject_eGY_augxLYc_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17edf96ac4b107adef1d56bbd4c501b71a85863866feb9f3a8847dfaf77f1a2c"

  strings:
    $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>    <requestedPrivileges>     <requestedExecutionLevel  level=\"" ascii
    $s3 = "For Computer" fullword wide
    $s4 = "Infinitely" fullword wide
    $s5 = "mistic" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}