rule Virus_Hijack_Trojan_GenericKDZ_105924_565_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_565_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "203ff8d4644b41fee2fc88146814f261ff272ff0a57ac9296e137a6aab5b411f"

  strings:
    $s1 = "K>TAbU$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}