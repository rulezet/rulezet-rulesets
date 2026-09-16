rule Virus_Hijack_GenPack_Backdoor_Hangup_B_304 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_304.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da84f2d023c34bf914d46ec6a07f0d38f65c3cbdc7abff4bd94c6e02aee7e9b5"

  strings:
    $s1 = "0of the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}