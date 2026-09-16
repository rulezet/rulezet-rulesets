rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_aOF3i8p_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b291f28a729d4b9959c6846bdeed1904d35e6df8d1aa66b05d0c9b70c835cd86"

  strings:
    $s1 = "##APaR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}