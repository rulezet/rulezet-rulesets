rule VirusShareTrojanSiggen1527233_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1527233_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7471293102d9a2f933dd7faacdf2ca19735b4b9b6a2bda78c4e11efbd44bb44d"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}