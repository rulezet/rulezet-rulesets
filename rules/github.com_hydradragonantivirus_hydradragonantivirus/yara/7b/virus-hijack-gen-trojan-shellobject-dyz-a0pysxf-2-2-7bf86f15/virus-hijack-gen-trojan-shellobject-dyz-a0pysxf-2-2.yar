rule Virus_Hijack_Gen_Trojan_ShellObject_DyZ_a0Pysxf_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DyZ@a0Pysxf_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87e9493ed28b753bcadfc4e8672061bc70e54aabe9237ea9e827782863f8b1e8"

  strings:
    $s1 = ",@SPeal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}