rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aCZnhbe_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aCZnhbe_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193280569480ca0322d699703a532ae4acffeed1304a8f4fa46b4dcd81fe866d"

  strings:
    $s1 = "/0available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}