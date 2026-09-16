rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_266_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_266_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30c9942afe5700629498c5d690ead7b36517d484546a77bc2f4565b5fbc7bdfe"

  strings:
    $s1 = "s<iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}