rule Virus_Hijack_Trojan_GenericKDZ_105924_132_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_132_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e05526bd6e7d03a406105c962a6cb654771ab3eb6813eefa8731e44ae0785c1"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}