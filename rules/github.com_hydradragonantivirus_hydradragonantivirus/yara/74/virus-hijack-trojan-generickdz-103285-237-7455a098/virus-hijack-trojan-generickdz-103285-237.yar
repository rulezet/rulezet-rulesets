rule Virus_Hijack_Trojan_GenericKDZ_103285_237 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_237.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2aa5758de49d7b64b893d4e1410a221f81ff7323272a6edd504f73bdc0b281a2"

  strings:
    $s1 = "-)(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s2 = "-)(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}