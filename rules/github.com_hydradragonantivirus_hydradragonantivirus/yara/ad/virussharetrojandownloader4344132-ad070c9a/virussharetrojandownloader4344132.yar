rule VirusShareTrojanDownLoader4344132 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4344132.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9107484d6e70243619fff580a013ac7814ad2f987a4aeafdc216e0709706b18b"

  strings:
    $s1 = "ROrY)vF" fullword ascii
    $s2 = "stEt{4" fullword ascii
    $s3 = "l (goof@" fullword ascii
    $s4 = "Z&BrOO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}