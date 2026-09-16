rule Virus_Hijack_Gen_Trojan_ShellObject_juZ_aKo42Jj_17_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_17_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "667c7b14414afbb649559484b50204e8a87c9e6a6579ca16a2e821a34a01673d"

  strings:
    $s1 = "y%sTEP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}