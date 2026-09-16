rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_ae0D4Vj_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@ae0D4Vj_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a95c8bf67d23e4e7c13c7493bb2ac7f8d8dd1ac3de46922d039c7780d7f3f34d"

  strings:
    $s1 = "Ia neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}