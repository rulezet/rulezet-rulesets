rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1792940353382036540a9cb6cdfab20191df2a581320e05011fa4b4cf6d0373e"

  strings:
    $s1 = "Alibaba software (Shanghai) Corporation." fullword wide
    $s2 = "Alibaba software (Shanghai) Corporation. All rights reserved." fullword wide
    $s3 = "<asmv1:assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv1=\"urn:schemas-microsoft-com:asm.v" ascii
    $s4 = "D$dORP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}