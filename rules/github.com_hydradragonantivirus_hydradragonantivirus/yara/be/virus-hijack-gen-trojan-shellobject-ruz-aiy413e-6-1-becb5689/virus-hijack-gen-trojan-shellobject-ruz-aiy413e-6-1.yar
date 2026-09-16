rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aiy413e_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aiy413e_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8a2ad6923135cc4bd29828b7f22346849914ea766543733a038894e1292c8c9"

  strings:
    $s1 = "shim:J@" fullword ascii
    $s2 = "+\"FUzz" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}