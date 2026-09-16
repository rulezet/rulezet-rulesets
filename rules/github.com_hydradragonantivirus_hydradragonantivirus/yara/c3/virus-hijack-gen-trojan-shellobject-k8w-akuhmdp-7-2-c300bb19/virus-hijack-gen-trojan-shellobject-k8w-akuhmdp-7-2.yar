rule Virus_Hijack_Gen_Trojan_ShellObject_k8W_aKuHmDp_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8W@aKuHmDp_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f09a5c064a5ce2e84af571b858c92927c8b70d32daa422d881afe460d92806fd"

  strings:
    $s1 = "-:URva" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}