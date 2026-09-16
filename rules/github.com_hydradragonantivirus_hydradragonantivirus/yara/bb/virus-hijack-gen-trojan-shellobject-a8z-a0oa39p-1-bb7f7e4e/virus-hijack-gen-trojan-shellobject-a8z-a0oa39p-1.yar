rule Virus_Hijack_Gen_Trojan_ShellObject_A8Z_a0oa39p_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.A8Z@a0oa39p_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e291fbdf6d4f91364f05de4149b979f31faebe375b9d43bcedee4e907a2240a"

  strings:
    $s1 = "availability of Extended Support and Extended Maintenance Supp" fullword ascii
    $s2 = "may renew your order for an additiona" fullword ascii
    $s3 = "$M in Managed Assets: is defined as one million U.S. dollars (Seven hundred and seventy-two thousand four hundredP" fullword ascii
    $s4 = "faPerson: is defined as your employee or contractor who is actively working on behalf of your organization or a former" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}