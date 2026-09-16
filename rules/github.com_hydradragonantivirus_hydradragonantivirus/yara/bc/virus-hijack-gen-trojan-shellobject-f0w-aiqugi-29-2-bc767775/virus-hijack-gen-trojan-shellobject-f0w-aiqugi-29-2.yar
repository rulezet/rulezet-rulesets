rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_29_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_29_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20eb6a00ec44a6b6c492cbd62ac2b60b58480290d4ac12f64d4fc957681a09e6"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
    $s2 = "4.7.2558.0 built by: NET471REL1" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}