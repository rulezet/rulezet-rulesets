rule Virus_Hijack_Gen_Variant_Doina_58391 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Doina.58391.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a32620530064260b1823ef43ef96db9c542cbfc2ef6a7a67bf8e1cb68b702ff9"

  strings:
    $s1 = "Dark EyE Coders" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}