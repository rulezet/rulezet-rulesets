import "pe"
rule _Trojan_Hooker_Gen_Variant_Ransom_Loki_2268_Virus_Hijack_Gen_Tro_43 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Gen.Variant.Ransom.Loki.2268.vir, Virus.Hijack_Gen.Trojan.ShellObject.dyX@amUgp3c_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c921db26e38084268c82cefc7cd8f16eaa9b3b6ea71a1b5e91b51e59b346278"
    hash2       = "26350df4815588eb47c1b92738168cebf8edfdb29ccc7c2146036a28ad2b81ab"

  strings:
    $s1 = "JOLT<GSnDC^MRDmCyvXFgYHVtTS" fullword ascii
    $s2 = "Un Uomo Solo" fullword ascii
    $s3 = "This Program Check Booking And Preservation" fullword wide
    $s4 = "Booking Checking V2" fullword wide
    $s5 = "Booking Check" fullword wide
    $s6 = "C.U.B.E Corp " fullword wide
    $s7 = "\\>AcME[" fullword ascii
    $s8 = "FASh;#" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f2d24d034ad8ae86f9dd9c6c9707e46f" and (all of them)
    ) or (all of them)
}