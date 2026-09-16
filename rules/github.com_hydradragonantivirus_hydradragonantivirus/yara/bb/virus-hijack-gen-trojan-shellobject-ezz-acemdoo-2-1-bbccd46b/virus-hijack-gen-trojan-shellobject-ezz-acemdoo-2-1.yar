rule Virus_Hijack_Gen_Trojan_ShellObject_ezZ_aCEmdoo_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ezZ@aCEmdoo_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43cc8291881d86373279a900ebff9687e51f209b2791370b63cd6a64a9713ad6"

  strings:
    $s1 = "Huff co" fullword ascii
    $s2 = "l image base: %X  New" fullword ascii
    $s3 = "nACe[1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}