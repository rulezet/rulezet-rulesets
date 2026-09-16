rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_12_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fde51496eca8e26dee74add912fdb143d33af4f165cf927298e9d1287cab99b4"

  strings:
    $s1 = "Csi Sync Client Interface Dll" fullword wide
    $s2 = "?Finish@CsiExternalWriteToTelemetryElapsed@Csi@@QAGXXZ" fullword ascii
    $s3 = "yMicrosoft Office Sync Client Interface" fullword wide
    $s4 = "Microsoft Office Document Cache Sync Client Interface" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}