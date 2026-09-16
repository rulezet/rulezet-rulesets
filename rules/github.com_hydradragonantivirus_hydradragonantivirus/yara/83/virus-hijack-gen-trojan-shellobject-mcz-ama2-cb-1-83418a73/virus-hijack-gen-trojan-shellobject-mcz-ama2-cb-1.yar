rule Virus_Hijack_Gen_Trojan_ShellObject_mCZ_ama2_Cb_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.mCZ@ama2@Cb_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98f5d23a62e39f6f9c98809aacc0318e02a43aa84eaa209ef8e2b11c0d2e760a"

  strings:
    $s1 = "microsoft.com/office/backup. You may not distribute the backup copy of the so" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}