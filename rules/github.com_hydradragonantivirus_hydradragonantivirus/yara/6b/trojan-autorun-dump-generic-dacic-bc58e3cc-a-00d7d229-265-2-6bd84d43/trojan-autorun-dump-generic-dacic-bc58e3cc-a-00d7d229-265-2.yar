rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_265_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_265_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92e2cc7980fc342c59860a0e6a16c73f10ee3b0caac53530121e89448933d305"

  strings:
    $s1 = "<Module>{e543bd13-ffe0-40b6-a13c-292395d9a1b4}" fullword ascii
    $s2 = "Atomic Wallet" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}