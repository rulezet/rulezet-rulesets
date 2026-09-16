rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_30_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2b6af12788984a1746d9b323525c312a6ea843066866f22f1cf83d577fbea7d"

  strings:
    $s1 = "Darkick Commander" fullword ascii
    $s2 = "Font(TD" fullword ascii
    $s3 = "Color`ND" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}