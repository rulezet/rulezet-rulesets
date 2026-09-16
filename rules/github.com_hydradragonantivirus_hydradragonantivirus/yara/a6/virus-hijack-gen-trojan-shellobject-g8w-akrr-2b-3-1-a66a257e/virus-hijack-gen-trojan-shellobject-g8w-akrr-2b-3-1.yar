rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aKrr_2b_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aKrr!2b_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a82037f1c639b275a2ae4c1ac59a80f36e5275929e63882a8aeeb8e01667cf9"

  strings:
    $s1 = "Http/1.1 403 Forbidden" fullword ascii
    $s2 = "Rich>M2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}