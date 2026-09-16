rule Virus_Hijack_Gen_Trojan_ShellObject_syZ_ayTyh0n_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.syZ@ayTyh0n_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58038a7720a2d949ab0c920dfc33e16096282457c8304f36b2fd70d9e086a907"

  strings:
    $s1 = "Cstring too long" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}