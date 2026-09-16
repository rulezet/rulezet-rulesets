rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aSl2g6j_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aSl2g6j_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95062d30d5ef49c3c512787bb7fe6866e79a6b58ec8a60b207e9056fc161c478"

  strings:
    $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}