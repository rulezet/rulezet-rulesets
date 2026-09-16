rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_ae0D4Vj_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@ae0D4Vj_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce055a6d208c3133ffee8558a85bad09a54d40f799701cda2aae9c03332d83fc"

  strings:
    $s1 = "j^a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}