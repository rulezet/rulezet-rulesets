rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_18_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_18_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "782f6f914d69d0ff3daba5cedbe0df672cfd11224d5299e2b332c817f6effa9a"

  strings:
    $s1 = "SMB Share For DevelopmentFiles path" fullword wide
    $s2 = "Deleting SMB Share For DevelopmentFiles path" fullword wide
    $s3 = "Developer Tools Service" fullword wide
    $s4 = "=)bAsh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}