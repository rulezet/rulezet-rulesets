rule Trojan_Autorun_Gen_Variant_Barys_95064_9_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.95064_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e765b2c2a04f464bd36d3cdd48140f02dda5b1ba97681a18f559894ab788863"

  strings:
    $s1 = "\\or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}