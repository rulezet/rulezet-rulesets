rule Virus_Hijack_Gen_Trojan_ShellObject_ByZ_aSgChKg_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ByZ@aSgChKg_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "424034d90145a1dddc0bc38663c89d9613ed2b3dab69ed926a4751f293c75758"

  strings:
    $s1 = "D<WoNt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}