rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_49_1_Virus_Hijac_176 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_49_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_50_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a27acaeaa9b50b7d7d2e2e334259f1f70552999712199b53c416c854c362a73"
    hash2       = "f8bcaa2c085b0f51e6662784141ac032264644dc799f91a0b2708c1c187cb533"

  strings:
    $s1 = "DBCombo ActiveX Control - Version 6.0 (SP3) " fullword wide
    $s2 = "DBList ActiveX Control - Version 6.0 (SP3) " fullword wide
    $s3 = "!DBCombo General Property Page" fullword ascii
    $s4 = "Microsoft Data Bound List Controls 6.0 (SP6)WW" fullword ascii
    $s5 = ",Microsoft Data Bound List Controls 6.0 (SP6)" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}