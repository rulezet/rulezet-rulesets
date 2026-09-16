rule Virus_Hijack_Trojan_GenericKDZ_98113_257_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_257_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91deb1bd85ce75a4163ee4948b5f0ba5c13c4e0f710e22b94e50a23ae42ed67f"

  strings:
    $s1 = "z]CUbE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}