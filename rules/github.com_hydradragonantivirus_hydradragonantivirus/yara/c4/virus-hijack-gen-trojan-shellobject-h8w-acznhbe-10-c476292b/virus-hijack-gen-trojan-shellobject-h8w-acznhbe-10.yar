rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912c32ef644a5093271f23cf36873c0913ae7981cdbe0ae94f2c42c867a38a87"

  strings:
    $s1 = "tavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}