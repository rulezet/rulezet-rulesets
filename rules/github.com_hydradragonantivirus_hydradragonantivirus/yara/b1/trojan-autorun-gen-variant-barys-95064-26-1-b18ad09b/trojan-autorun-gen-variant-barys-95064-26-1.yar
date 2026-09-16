rule Trojan_Autorun_Gen_Variant_Barys_95064_26_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.95064_26_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcc2f30fde097c3828528f389afaffef8b01882f854f9119e6f069dbaeaa43a3"

  strings:
    $s1 = "$_hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}