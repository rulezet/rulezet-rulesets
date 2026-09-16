rule Virus_Hijack_Gen_Trojan_ShellObject_kAZ_aCEmdoo_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.kAZ@aCEmdoo_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "050a0c23795d7391e866d9e8c439b6764fe410e7dc4ea9bb2fdd7ebb5e90707f"

  strings:
    $s1 = "; name" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}