rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aag1Gcl_22_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aag1Gcl_22_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f098737a0b13e9129123e1fa03e34a8473421fe818282fe8e58ca6749dce747"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
    $s2 = "4.7.2558.0 built by: NET471REL1" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}