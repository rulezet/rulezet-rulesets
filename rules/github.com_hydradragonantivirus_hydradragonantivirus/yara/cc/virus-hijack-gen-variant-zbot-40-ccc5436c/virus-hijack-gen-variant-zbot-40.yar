rule Virus_Hijack_Gen_Variant_Zbot_40 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Zbot.40.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09984a9894b9c91c3c653c00965068ca83b9b829d1be9a9b01709153d98fbb31"

  strings:
    $s1 = "shatterheaded" fullword wide
    $s2 = "loiterer" fullword wide
    $s3 = "Daintiness" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}