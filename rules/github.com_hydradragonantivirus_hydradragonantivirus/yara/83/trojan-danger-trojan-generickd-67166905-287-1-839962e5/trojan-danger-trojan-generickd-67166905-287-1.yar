rule Trojan_Danger_Trojan_GenericKD_67166905_287_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_287_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78c151d4d2662773518c8ce5da154ede28322690061dcdd40b225c17a0d4f7ae"

  strings:
    $s1 = "f(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = "f(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}