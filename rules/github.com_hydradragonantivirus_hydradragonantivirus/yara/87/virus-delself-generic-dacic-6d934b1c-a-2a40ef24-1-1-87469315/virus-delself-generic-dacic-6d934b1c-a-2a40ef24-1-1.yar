rule Virus_Delself_Generic_Dacic_6D934B1C_A_2A40EF24_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Delself_Generic.Dacic.6D934B1C.A.2A40EF24_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d26398810385707a811f5633cd77dddab5c7b50f2a8e304d23e312e558ffbf4d"

  strings:
    $s1 = "TRap?<nau" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}