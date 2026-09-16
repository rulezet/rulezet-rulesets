rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aWlu0Qk_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aWlu0Qk_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2730c3da23d72473aad984c225ab7a0293ab58c866f60b5c398c947df491d6b"

  strings:
    $s1 = "HoVe::," fullword ascii
    $s2 = "Kelt(28" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}