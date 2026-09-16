rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aCZnhbe_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aCZnhbe_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe872b99e85355d1d845aa0484b6413d3739c91dc2a0cad86f0fd8d07ad30a1b"

  strings:
    $s1 = "ibavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}