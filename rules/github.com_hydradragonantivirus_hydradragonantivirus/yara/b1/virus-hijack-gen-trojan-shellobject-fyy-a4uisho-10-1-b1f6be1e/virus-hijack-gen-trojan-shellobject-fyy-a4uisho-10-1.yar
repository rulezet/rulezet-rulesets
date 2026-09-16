rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da88bb83bb317976e1de9c6e67408ee360a639bfbace296a453dae8624cd7a7a"

  strings:
    $s1 = "<description>GoappbestInst</description>" fullword ascii
    $s2 = "think probably it was quite an attractive" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}