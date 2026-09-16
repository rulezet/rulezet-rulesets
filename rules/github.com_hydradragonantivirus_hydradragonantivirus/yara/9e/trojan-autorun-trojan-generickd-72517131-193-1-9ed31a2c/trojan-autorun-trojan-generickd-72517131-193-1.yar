rule Trojan_Autorun_Trojan_GenericKD_72517131_193_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_193_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b380aa9b7d182cb097620fa430cb9e9f993d1bd6a07de853ac13f7f63e287405"

  strings:
    $s1 = "required and all actual users must be license" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}