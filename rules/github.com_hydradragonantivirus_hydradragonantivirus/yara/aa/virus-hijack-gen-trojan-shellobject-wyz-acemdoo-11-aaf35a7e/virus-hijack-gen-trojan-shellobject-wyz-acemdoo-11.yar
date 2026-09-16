rule Virus_Hijack_Gen_Trojan_ShellObject_WyZ_aCEmdoo_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.WyZ@aCEmdoo_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fac139b3e37076e54c35a84cdfb6b75f0599f12b4bf81d7e0ff06fdb1d64df9b"

  strings:
    $s1 = "lATA>cNM*x" fullword ascii
    $s2 = "coRN#~" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}