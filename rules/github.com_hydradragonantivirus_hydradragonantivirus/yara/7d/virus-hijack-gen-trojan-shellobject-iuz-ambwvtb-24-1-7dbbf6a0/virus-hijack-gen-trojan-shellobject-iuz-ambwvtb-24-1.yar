rule Virus_Hijack_Gen_Trojan_ShellObject_iuZ_amBwvTb_24_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iuZ@amBwvTb_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9789365341421996eca18d5db0ab657e21499adcca6bbe5ad4b63212911a974d"

  strings:
    $s1 = "!Error Down" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}