rule Virus_Hijack_Trojan_GenericKDZ_74550_146_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_146_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1688b435c46575b89e3b59a3112fb344714870c8642b75d1d76fbb8636380e28"

  strings:
    $s1 = "v;lysSa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}