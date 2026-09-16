rule Virus_Hijack_Trojan_GenericKDZ_103285_645 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_645.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b9fb8796cad45c5d3ab6743d8ba59c4d502439bee17cf88e2b3f549fbb0fa88"

  strings:
    $s1 = "Havailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}