rule Virus_Hijack_Gen_Trojan_ShellObject_p8W_aCNb4Uo_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b299b71b3aef944355f498e2f40bbbc9734615c521efe97474574dced13af8af"

  strings:
    $s1 = "CORE;5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}