rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02181009cbb2a8787ddaadc6597fa28cf8314d11a5e0d6a59bde7c57638eb5cf"

  strings:
    $s1 = "hOTI?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}