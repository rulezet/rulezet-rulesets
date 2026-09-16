rule Virus_Hijack_Gen_Trojan_ShellObject_r0Z_a4Zmumi_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r0Z@a4Zmumi_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f49335a642db6ceeb62efb0cd9a16e05e470d5e757ea5f2556155764188ad7d"

  strings:
    $s1 = "]sOle:^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}