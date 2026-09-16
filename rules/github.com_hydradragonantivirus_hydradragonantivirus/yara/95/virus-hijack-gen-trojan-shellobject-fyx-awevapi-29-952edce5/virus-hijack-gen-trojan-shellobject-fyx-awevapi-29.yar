rule Virus_Hijack_Gen_Trojan_ShellObject_fyX_aWevApi_29 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyX@aWevApi_29.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f0231c1524d24a5dbc7919a688de82ebed3cc0fbefec932c8bcab4ef8e91ab4"

  strings:
    $s1 = "<description>Java(TM) SE appletviewer process</description>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}