rule Virus_Hijack_Gen_Trojan_ShellObject_WyZ_aCEmdoo_28 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.WyZ@aCEmdoo_28.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "580f0dcd8443b50bf905b3589b1d638a8d09a134239e91929bcece2f09d10862"

  strings:
    $s1 = "g]ya rule" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}