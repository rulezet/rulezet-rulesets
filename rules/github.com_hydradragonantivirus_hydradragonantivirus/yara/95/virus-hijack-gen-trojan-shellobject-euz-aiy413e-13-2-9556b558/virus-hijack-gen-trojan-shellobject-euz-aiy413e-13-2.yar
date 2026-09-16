rule Virus_Hijack_Gen_Trojan_ShellObject_EuZ_aiy413e_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca7363290c1c431615acca55385c95a97d1c1ebe7092cab254265271834983ae"

  strings:
    $s1 = "Lino:S^k" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}