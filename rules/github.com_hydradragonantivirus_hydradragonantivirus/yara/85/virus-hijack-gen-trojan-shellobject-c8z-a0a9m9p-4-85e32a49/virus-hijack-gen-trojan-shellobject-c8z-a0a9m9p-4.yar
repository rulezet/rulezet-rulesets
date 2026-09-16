rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_a0a9m9p_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@a0a9m9p_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c7438e64eca23dbd379e484878f3c3a78f1708016664561362ead42ada39836"

  strings:
    $s1 = "ASoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}