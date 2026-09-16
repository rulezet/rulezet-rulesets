rule Virus_Hijack_Trojan_GenericKDZ_74550_223 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_223.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1549fa315a69114085f0fd5a6de08b5022ed84b77cf2765769327dc6fe2d4ea2"

  strings:
    $s1 = "x>exES" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}