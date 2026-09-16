rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_82_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_82_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "508c02a40ea9b6726da009b948c9a64b40da6128de83b455a36f2ad33fc40c2d"

  strings:
    $s1 = "Microsoft(C) Windows(C) Operating System" fullword wide
    $s2 = ":string too lo" fullword ascii
    $s3 = "Unknown excepE" fullword ascii
    $s4 = "\",valid 7posi{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}