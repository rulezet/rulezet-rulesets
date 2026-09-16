rule Virus_Hijack_Gen_Trojan_ShellObject_z8Z_aCZnhbe_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.z8Z@aCZnhbe_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c1603ed40019f009b07dcf618bef3510bacee5ecc1f64c844e5e6ed2b50db0a"

  strings:
    $s1 = "!available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}