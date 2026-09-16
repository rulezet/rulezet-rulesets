rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "750503ff19e1188d28a562a68a026d0d0429d1714f0cc6010c6b83e944dede59"

  strings:
    $s1 = "bITo<3F" fullword ascii
    $s2 = "L]Sasa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}