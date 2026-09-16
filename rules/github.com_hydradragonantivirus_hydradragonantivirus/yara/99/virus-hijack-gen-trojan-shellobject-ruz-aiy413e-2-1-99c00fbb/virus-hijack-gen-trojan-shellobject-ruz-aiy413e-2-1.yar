rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aiy413e_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aiy413e_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4417a9ccefe2be33f49877aa7eaf597ddb1087cc8d312bd6e679c86f0f75b8e1"

  strings:
    $s1 = "oMAO*M" fullword ascii
    $s2 = ".AY`haDE" fullword ascii
    $s3 = "aE8#skEIn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}