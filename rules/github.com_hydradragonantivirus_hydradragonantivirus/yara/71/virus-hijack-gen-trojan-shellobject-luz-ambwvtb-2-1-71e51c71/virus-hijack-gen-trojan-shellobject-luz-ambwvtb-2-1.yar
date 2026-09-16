rule Virus_Hijack_Gen_Trojan_ShellObject_luZ_amBwvTb_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.luZ@amBwvTb_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b28168136c1e2a2d81d22d46d6b349719bf773396d0e27b010ec67d91759d42"

  strings:
    $s1 = "Cola]6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}