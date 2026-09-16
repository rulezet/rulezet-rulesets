rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_23_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09c427f36f283cdc38c175023e4748d7692fe1ee20540bbdd1e4b1b0da205b00"

  strings:
    $s1 = "cand hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}