rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d838d4e5f899ddf0044673f6a7997f327c755c0ef9d99a3fae0e8dd04bb8c0f"

  strings:
    $s1 = "Rencounter" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}