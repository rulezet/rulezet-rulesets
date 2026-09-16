rule Virus_Hijack_Gen_Trojan_ShellObject_fyX_aWevApi_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyX@aWevApi_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "873f008416596eda9c1388b6c43b968fbf5f2b5c1bb188d3489ad892d35c59e8"

  strings:
    $s1 = "<description>Java(TM) SE javap process</description>" fullword ascii
    $s2 = "GUID passed by Logsession is written to registry" fullword ascii
    $s3 = "Copyright 2008-15 Adobe Systems Incorporated. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}