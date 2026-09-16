rule Virus_Hijack_Gen_Trojan_ShellObject_mCZ_ama2_Cb_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.mCZ@ama2@Cb_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d538af8817dd00207a4b5be9a7f3d76ebdf326af445b416999b7d29305618b4"

  strings:
    $s1 = "microsoft.com/office/backup. You may not distribute the backup copy of the so" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}