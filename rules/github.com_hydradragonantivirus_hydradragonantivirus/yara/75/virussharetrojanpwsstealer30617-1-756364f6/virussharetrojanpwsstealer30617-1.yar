rule VirusShareTrojanPWSStealer30617_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPWSStealer30617_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9d21350ab23cca7e46d77644e2bedd11fd4aa586be7984cc19973dbdef5937b"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}