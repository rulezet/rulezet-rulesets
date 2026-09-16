rule Virus_Hijack_Trojan_GenericKDZ_103285_574 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_574.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acf4b0965486c28032359d9baf31269fab7848d04f9e24e55a4c3b6c054888d3"

  strings:
    $s1 = "bavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}