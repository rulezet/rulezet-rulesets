rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_aWV0B1k_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@aWV0B1k_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46746455f7c76b8806b8268daa5b767b940469327627d95a597abe8fa9bf124c"

  strings:
    $s1 = ">?NiDe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}