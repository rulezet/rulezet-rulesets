import "pe"
rule _Trojan_Sysbot_Trojan_GenericKDZ_95132_Trojan_Sysbot_Trojan_Gene_408 {
  meta:
    description = "datamaliciousorder - from files Trojan.Sysbot_Trojan.GenericKDZ.95132.vir, Trojan.Sysbot_Trojan.GenericKDZ.95132_1.vir, Trojan.Sysbot_Trojan.GenericKDZ.95132_2.vir, Trojan.Sysbot_Trojan.GenericKDZ.95132_3.vir, Trojan.Sysbot_Trojan.GenericKDZ.95132_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6b2a57891b3daf7a61b8765f22000b190e765fc3923c3cf03c5081290a2b449"
    hash2       = "6f2d55092d154fd6012ddea914b9e011f9944255262e8eb6caa177c9173971d9"
    hash3       = "12245e2cfc1296b8f3abfb292a35239beaf63fd756515ff5ca24fc053ec3cc04"
    hash4       = "557f3168f022d96e2907a5de53f9b599d69264c99ccede2e0206c986d465a8f8"
    hash5       = "db57cee37912d7dcfd50d554cbb8d47943cc7f597bc102d71b16921bcff79911"

  strings:
    $s1  = "*\\AM:\\crot\\caches\\Secret Project Final\\babon\\babon.vbp" fullword wide
    $s2  = "Babon's Computer" fullword wide
    $s3  = "Welcome Friend" fullword wide
    $s4  = "Babon Corporation" fullword wide
    $s5  = "Please enjoy the Babon Entertainment ^_^" fullword wide
    $s6  = "Windows Title" fullword wide
    $s7  = "Jangan terlalu banyak bejalanan n menghabiskan waktu pakai hal2 yang kda penting" fullword wide
    $s8  = "Just wanna say : Hello Friend.. Moci-moci ^^" fullword wide
    $s9  = "By : Anak Sampit yang lagi menuntut ilmu di pulau seberang" fullword wide
    $s10 = "Sampit Community.. " fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "fce46a6dd6a779730657e2b99c66e821" and (all of them)
    ) or (all of them)
}