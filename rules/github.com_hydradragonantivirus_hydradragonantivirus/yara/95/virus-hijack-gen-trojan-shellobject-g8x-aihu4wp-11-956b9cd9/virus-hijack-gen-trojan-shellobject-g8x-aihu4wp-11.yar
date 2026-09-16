rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aiHu4Wp_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aiHu4Wp_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9fbe24812f8d6cf4de318f93c47aa96e01fd1803236957a3837afafd46eaa64"

  strings:
    $s1 = "C6What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}