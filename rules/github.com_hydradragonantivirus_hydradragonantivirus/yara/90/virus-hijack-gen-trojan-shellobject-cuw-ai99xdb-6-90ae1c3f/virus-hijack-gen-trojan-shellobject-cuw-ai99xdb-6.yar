rule Virus_Hijack_Gen_Trojan_ShellObject_cuW_ai99xDb_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.cuW@ai99xDb_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b99e40915078393763b9e731d03b15749c3882627fd95b698daf13b4cb6649b"

  strings:
    $s1 = "]SaDe;" fullword ascii
    $s2 = "@)SaMp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}