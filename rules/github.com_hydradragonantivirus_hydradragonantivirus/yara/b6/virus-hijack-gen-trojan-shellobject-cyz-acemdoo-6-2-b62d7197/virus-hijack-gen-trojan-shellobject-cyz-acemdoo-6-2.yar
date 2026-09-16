rule Virus_Hijack_Gen_Trojan_ShellObject_CyZ_aCEmdoo_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.CyZ@aCEmdoo_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3171b251e10d7fc5680bd1dd2290b52f1ff9f76fe0c8b45b5127db912e55f7be"

  strings:
    $s1 = "(NASi'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}