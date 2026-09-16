rule Virus_Hijack_Gen_Trojan_ShellObject_z8Z_aOYcrUm_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.z8Z@aOYcrUm_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfdf3403f88e6ff86857e0ad3c8c39cbf206412ab7f72b801f93f956398995dc"

  strings:
    $s1 = "f7:^~tM|dxYg7^QgreQvc7zkg{Pare?O^rGc{xMv9rGv7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}