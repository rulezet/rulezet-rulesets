rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOqOUDe_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOqOUDe_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a26b5ed64badbbb88cfb6a388a1e89a3fc3d80e6842caa3e3f855fa103ef9f7"

  strings:
    $s1 = "Profiler detected" fullword wide
    $s2 = "Loop broken" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}