rule Trojan_Danger_Trojan_GenericKD_67166905_160_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_160_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a57b8189a0371c248573a137aaaedbe5bd00196e2cd8b40a3e48f9e007ca14ae"

  strings:
    $s1 = "1-virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}