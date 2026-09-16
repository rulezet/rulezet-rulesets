rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddbe53474b6f6c2eb40c51297bb862888b382ae1e8dd3582590ce09245dbde15"

  strings:
    $s1 = "wAiT) " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}