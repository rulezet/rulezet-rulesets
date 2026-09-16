rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f7f358dd9e59dc4ebc4a5b2f0001a073e91ff19d33edc18eb11904753f33f5f"

  strings:
    $s1 = "v|Lb]M[COIn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}