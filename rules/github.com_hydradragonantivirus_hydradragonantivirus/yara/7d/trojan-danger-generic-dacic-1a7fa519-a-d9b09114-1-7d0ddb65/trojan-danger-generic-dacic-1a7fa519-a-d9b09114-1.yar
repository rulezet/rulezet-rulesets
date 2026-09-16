rule Trojan_Danger_Generic_Dacic_1A7FA519_A_D9B09114_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.D9B09114_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbf3502fd032079cdd28091d4886ede210e48e23aead84d993ee385a6146a815"

  strings:
    $s1 = "!University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}