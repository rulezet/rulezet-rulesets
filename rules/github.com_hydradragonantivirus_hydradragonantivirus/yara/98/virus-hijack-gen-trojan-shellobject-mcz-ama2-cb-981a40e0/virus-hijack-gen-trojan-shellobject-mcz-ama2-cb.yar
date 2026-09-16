rule Virus_Hijack_Gen_Trojan_ShellObject_mCZ_ama2_Cb {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.mCZ@ama2@Cb.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2923cab82d504cde4d2cec4d8a9389c8905c244418e8dea8ef503a0d9061e7de"

  strings:
    $s1 = "microsoft.com/office/backup. You may not distribute the backup copy of the so" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}