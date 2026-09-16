rule Trojan_Danger_Generic_Dacic_1A7FA519_A_0C921389_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.0C921389_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e74a97a3b3d4ac09c63147a7fb7aa3b4afbf1cabe0aba0e534676affae1a9b7"

  strings:
    $s1 = "[available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}