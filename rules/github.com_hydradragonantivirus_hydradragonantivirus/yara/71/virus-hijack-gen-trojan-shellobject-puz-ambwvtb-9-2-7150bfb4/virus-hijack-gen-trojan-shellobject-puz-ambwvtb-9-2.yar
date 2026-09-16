rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2a8db0360b853dac095a3beccc1b8a6ad1177da11c8cdfa458bc95791c287f5"

  strings:
    $s1 = "TeAM[=" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}