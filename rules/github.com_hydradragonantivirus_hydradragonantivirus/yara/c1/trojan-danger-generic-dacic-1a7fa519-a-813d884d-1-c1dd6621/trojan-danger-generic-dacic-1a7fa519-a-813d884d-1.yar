rule Trojan_Danger_Generic_Dacic_1A7FA519_A_813D884D_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.813D884D_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0d515050004cf0aba3ace9397166c1ceb5ea55bb244685e6a54b2c66c8b93e8"

  strings:
    $s1 = "((including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = "((including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}