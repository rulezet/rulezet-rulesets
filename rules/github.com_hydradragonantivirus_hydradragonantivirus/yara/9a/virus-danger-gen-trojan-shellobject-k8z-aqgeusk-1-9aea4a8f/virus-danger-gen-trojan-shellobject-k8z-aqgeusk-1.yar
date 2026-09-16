rule Virus_Danger_Gen_Trojan_ShellObject_k8Z_aqgEuSk_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.k8Z@aqgEuSk_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06613449594e50c32490c868ee49b73a93d417f667839302ffab330ba2f18e50"

  strings:
    $s1 = "Microsoft Office PowerPoint 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}