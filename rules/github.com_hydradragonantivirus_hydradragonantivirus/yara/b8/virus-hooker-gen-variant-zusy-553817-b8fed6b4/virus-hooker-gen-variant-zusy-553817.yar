rule Virus_Hooker_Gen_Variant_Zusy_553817 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Gen.Variant.Zusy.553817.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "083deea1e54404e7c6af0ab56281cf40aaca5b6694437e43aa266bc178d42684"

  strings:
    $s1 = "Bighead" fullword ascii
    $s2 = "Supportive" fullword ascii
    $s3 = "autoerotism" fullword ascii
    $s4 = "Accessibly" fullword ascii
    $s5 = "Flavorful" fullword ascii
    $s6 = "Aldermanic" fullword ascii
    $s7 = "Punctuality" fullword ascii
    $s8 = "Cotangent" fullword ascii
    $s9 = "Borage" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}