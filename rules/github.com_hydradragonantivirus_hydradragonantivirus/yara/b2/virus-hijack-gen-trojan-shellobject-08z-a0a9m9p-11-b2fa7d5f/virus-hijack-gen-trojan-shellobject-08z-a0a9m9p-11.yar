rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_a0a9m9p_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a13bdff77c2b025805004305018685675b39e5341bf2bb94cc27be61f45168d3"

  strings:
    $s1 = "s\"Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}