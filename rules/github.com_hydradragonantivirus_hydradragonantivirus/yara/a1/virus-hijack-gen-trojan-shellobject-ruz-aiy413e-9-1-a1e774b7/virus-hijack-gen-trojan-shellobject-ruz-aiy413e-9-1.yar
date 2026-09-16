rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aiy413e_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aiy413e_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb37d5ebfbd5880f210faccb781d3028bdc3f6e6210ed9ca30bc4c2992848709"

  strings:
    $s1 = "r*KIel" fullword ascii
    $s2 = "@[jAIl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}