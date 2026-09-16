rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_ae0D4Vj_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@ae0D4Vj_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "baa52d7d64f081d15db668f9b0539bd83f4187603a043fa177496dd56d78518c"

  strings:
    $s1 = "D^a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}