import "pe"
rule _Virus_Hijack_Dropped_Backdoor_Padodor_BJ_156_1_Virus_Hijack_Dro_492 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Dropped.Backdoor.Padodor.BJ_156_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_17_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_221_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_257_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cae7042cd1c3be15008fd0ae57bb5f657ca71ef86b83d18cd127a7efd7778ac"
    hash2       = "16eaa4e14d3b6d740d567f8f4d598a81f1b0539d417102a9562133e790c8b702"
    hash3       = "85177dec28a0f50e9d6f2911aabba50ddc7ff282492ec6f132d5eb4eb7b3151c"
    hash4       = "af8a0cbe8bc0bf10358489996ef6d6e775fcc9b094df7b14490ee71101dddf33"

  strings:
    $s1 = "Application Execution ErrorbInsufficient memory to run this application; close one or more Windows applications and try again." fullword wide
    $s2 = "Unexpected DOS error: %d." fullword wide
    $s3 = "Please uncompress it and try again.fOne of the library files needed to run this application is damaged. Please reinstall this ap" wide
    $s4 = "7Access to the specified device, path or file is denied.?This application requires a newer version of Microsoft Windows.:The spe" wide
    $s5 = "The path is invalid.*Too many other files are currently in use." fullword wide
    $s6 = "PThe application has chosen not to close.  It may be completing a lengthy task.  _Forcing the application to close may lose data" wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "62a960f8ad30d2ced6e939ce901644b8" and (all of them)
    ) or (all of them)
}