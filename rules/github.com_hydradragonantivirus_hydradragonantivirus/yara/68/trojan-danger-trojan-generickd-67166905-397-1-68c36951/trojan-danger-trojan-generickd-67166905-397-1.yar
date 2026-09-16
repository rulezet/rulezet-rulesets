rule Trojan_Danger_Trojan_GenericKD_67166905_397_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_397_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e89b1e263ea44223bfe367d44b08b2fce8782034bbe4bd128a9ff876c5888f0"

  strings:
    $s1 = "?V(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s2 = "?V(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}