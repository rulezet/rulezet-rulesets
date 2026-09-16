rule Virus_Hijack_Trojan_GenericKDZ_103285_427 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_427.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7017ffbb83ec9a44b9bab89aba029069deaa71f938db6a803b6cfcd08d6e2cbf"

  strings:
    $s1 = "Epurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii
    $s2 = "J}SaIp" fullword ascii
    $s3 = "#\"SaIp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}