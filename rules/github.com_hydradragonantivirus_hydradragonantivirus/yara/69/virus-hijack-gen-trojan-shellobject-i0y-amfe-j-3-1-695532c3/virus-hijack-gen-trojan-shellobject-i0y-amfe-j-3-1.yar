rule Virus_Hijack_Gen_Trojan_ShellObject_i0Y_amFE__j_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Y@amFE@@j_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e83f1b7715fd8b6fd46ed8d641b0dd5c01f8ad69a749758b55dd3dcf347a92f9"

  strings:
    $s1 = "Adobe Acrobat Reader DC " fullword ascii
    $s2 = "Adobe Acrobat Reader DC" fullword ascii
    $s3 = "VCopyright 1984-2021 Adobe Systems Incorporated and its licensors. All rights reserved." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}