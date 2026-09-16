rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cf5b966ebc9a1ca83c09db8b079283b12061d8d2f11cd771f0d4c44669666a5"

  strings:
    $s1 = "include more than one version, su`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}