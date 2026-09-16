rule Virus_Hijack_Gen_Trojan_ShellObject_uGZ_ayM4QWg_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3da59e38f6988f45278409a77cac70498f4b1c4eefb8def690555f0869ddf16"

  strings:
    $s1 = "`LACk&A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}