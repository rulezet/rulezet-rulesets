rule _Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_7_2_Virus_Hijac_87 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6acd9e939af0e51f7457309969b8bdb570e1a66b0869020c28ba9131e8c665a"
    hash2       = "675a83c85331defc03b5111af8b82242b3cfd7cd3b6eff86b70b4be3a0ff8b08"

  strings:
    $s1  = " Office Upload Center</description>" fullword ascii
    $s2  = "CUser action for selecting exit on toplevel UI frame." fullword wide
    $s3  = "?Increment@CLKRHashTable_Iterator@LKRhash@@QAE_NXZ" fullword ascii
    $s4  = "?Record@CLKRLinearHashTable_Iterator@LKRhash@@QBEPBXXZ" fullword ascii
    $s5  = "?Size@CLKRLinearHashTable@LKRhash@@QBEKXZ" fullword ascii
    $s6  = "?Clear@CLKRLinearHashTable@LKRhash@@QAEXXZ" fullword ascii
    $s7  = "?Record@CLKRHashTable_Iterator@LKRhash@@QBEPBXXZ" fullword ascii
    $s8  = "?Increment@CLKRLinearHashTable_Iterator@LKRhash@@QAE_NXZ" fullword ascii
    $s9  = "@Framework::CFrame" fullword wide
    $s10 = "@Framework::CFrameApp" fullword wide
    $s11 = "Ahttp://office/14/team/workspaces/specs/Office Sync Center.docx" fullword wide
    $s12 = "@Microsoft Office Upload Center" fullword wide
    $s13 = "?Abandon@CsiExternalWriteToTelemetryElapsed@Csi@@QAGXXZ" fullword ascii
    $s14 = "@Office Places" fullword wide
    $s15 = "@Clear" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}