rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ae2012899f86dedb6ff24dc2f5f60975bf5b5ad574efdf9a271bc5833cca64f"

  strings:
    $s1 = "COMPUTER BILD Digital GmbH1" fullword ascii
    $s2 = "COMPUTER BILD Digital GmbH0" fullword ascii
    $s3 = "@Floating point (%%e, %%f, %%g, and %%G) is not supported by the WTL::CString class." fullword wide
    $s4 = "voAR$8P*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}