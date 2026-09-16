rule Virus_Hijack_Gen_Trojan_ShellObject_uGZ_ayM4QWg_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca19e71ae296e637960c96e402a22632e8aba1abe00db4df77ad10b470f92a37"

  strings:
    $s1 = "\"Altern>" fullword ascii
    $s2 = "File*?Y" fullword ascii
    $s3 = "sc quota" fullword ascii
    $s4 = "Retry<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}