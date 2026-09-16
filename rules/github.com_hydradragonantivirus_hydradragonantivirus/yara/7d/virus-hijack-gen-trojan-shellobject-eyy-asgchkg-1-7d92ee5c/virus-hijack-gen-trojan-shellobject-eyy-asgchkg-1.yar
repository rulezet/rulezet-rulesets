rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aSgChKg_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aSgChKg_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edb80e806f0742ca32198dc53caf20e295b0465e86a0a148382b70ed8925f27c"

  strings:
    $s1 = "Application transferred[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}