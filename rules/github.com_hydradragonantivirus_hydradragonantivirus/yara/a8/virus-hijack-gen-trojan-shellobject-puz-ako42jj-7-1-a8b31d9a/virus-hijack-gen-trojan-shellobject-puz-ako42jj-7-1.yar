rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_aKo42Jj_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efe77ada3342b26b0e1a3e851ea9f951ae08c97ed9eccf387ae68e220762c1ac"

  strings:
    $s1 = "wRoX`9W" fullword ascii
    $s2 = "(cz?>darg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}