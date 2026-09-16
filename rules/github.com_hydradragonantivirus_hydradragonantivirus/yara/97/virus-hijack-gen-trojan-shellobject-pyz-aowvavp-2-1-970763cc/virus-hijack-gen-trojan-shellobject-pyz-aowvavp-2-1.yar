rule Virus_Hijack_Gen_Trojan_ShellObject_pyZ_aOWVavp_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aOWVavp_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9a0a5db1e1d5058b3763a26a10ea50588f839b7ec1746a7a109e6f049a96e46"

  strings:
    $s1 = "U*I`quAG" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}