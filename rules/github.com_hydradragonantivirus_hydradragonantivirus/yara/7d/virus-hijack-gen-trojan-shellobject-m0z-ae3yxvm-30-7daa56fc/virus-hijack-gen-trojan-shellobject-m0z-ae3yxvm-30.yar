rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_30 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_30.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37264472b32b1968a348c1837d58d4e01c892f100498b13b89f8cd70af6384b8"

  strings:
    $s1 = "V4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}