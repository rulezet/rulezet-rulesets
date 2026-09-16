rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_7_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23637601fc7a6c78cc2c3dc9b24de5f6a6361fc048c35a6a6546b52df2183899"

  strings:
    $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s3 = "soNK{^`" fullword ascii
    $s4 = "Copyright (C) 2009 Secure By Design Inc" fullword wide
    $s5 = ">sAiGA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}