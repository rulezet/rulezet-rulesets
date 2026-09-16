rule Virus_Hijack_Gen_Trojan_ShellObject_syZ_ayTyh0n_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.syZ@ayTyh0n_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b40d25468b653f1c457ae3c75c8f2300d174885ce7f9f3c8a8896ca25cac0b14"

  strings:
    $s1 = "Cstring too long" fullword ascii
    $s2 = "p#{PuXy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}