rule Virus_Hijack_Gen_Trojan_ShellObject_luZ_aWZUE8k_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.luZ@aWZUE8k_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fd88c22b799d35778ec31272cf734fd6ba72517ef9b9635e9d46ec0eb0ab01a"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
    $s2 = "4.7.2558.0 built by: NET471REL1" fullword wide
    $s3 = "gEum;_ 0" fullword ascii
    $s4 = "gAum;W" fullword ascii
    $s5 = "gRum;W" fullword ascii
    $s6 = "Rich;K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}