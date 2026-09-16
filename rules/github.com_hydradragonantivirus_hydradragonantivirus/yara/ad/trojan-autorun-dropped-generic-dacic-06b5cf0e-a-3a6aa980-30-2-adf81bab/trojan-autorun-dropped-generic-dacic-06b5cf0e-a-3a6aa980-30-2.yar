rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_30_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_30_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27cd0f7859462b5d611836a01d946a63870801ea815cf114016fed0640e5f359"

  strings:
    $s1 = "EMir`lS`PM" fullword ascii
    $s2 = ">z<tAHa;8" fullword ascii
    $s3 = "VixEN " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}