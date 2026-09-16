rule Virus_Hijack_Gen_Trojan_ShellObject_n8Z_a4IIY9p_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.n8Z@a4IIY9p_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5085a4429f1a24f335ac0063ba40d17882db36888ac3505af64d0969a95e318"

  strings:
    $s1 = "4.7.2558.0 built by: NET471REL1" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}