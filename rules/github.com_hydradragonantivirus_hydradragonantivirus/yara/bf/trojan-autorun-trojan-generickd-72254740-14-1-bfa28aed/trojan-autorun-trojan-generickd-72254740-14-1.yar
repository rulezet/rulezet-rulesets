rule Trojan_Autorun_Trojan_GenericKD_72254740_14_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72254740_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14cc0a8cfddaf9130fa48da66c7767b412abce120435dffd71761601d0ec2a08"

  strings:
    $s1 = "r4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}