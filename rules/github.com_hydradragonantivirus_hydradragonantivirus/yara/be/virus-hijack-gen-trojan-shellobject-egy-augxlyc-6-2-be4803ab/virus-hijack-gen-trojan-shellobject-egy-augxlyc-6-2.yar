rule Virus_Hijack_Gen_Trojan_ShellObject_eGY_augxLYc_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4a211aceed06bec30a8f6eeb8c543a03d2f63501c229400ea8d0ce097d27826"

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