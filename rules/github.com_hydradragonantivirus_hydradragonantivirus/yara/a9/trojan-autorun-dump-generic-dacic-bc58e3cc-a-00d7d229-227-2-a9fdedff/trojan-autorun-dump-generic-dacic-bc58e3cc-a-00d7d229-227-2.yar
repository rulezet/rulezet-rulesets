rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_227_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_227_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3289635b42828dccce10e57b6fc40aad6b9369c402dc97724137efc7c65dc35"

  strings:
    $s1 = "SELECT * FROM Win32_Process Where SessionId='{0}'" fullword wide
    $s2 = "HI! Write first number" fullword wide
    $s3 = "HI! Write second number" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}