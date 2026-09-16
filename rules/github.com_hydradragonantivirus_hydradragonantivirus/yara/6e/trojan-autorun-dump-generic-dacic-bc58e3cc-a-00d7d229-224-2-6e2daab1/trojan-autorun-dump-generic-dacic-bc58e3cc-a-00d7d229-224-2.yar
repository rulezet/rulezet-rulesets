rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_224_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_224_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db4f98133dd11d5b6a6e894c777bae318b8beb17effe21283ca133a39e461a3c"

  strings:
    $s1 = "Discord Link :  v1.0.0-custom" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}