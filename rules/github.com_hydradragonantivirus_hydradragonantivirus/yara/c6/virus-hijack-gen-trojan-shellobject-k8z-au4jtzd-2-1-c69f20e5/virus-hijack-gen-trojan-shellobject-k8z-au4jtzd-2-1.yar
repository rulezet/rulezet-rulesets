rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_au4JtZd_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@au4JtZd_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8734950116b8058dc8c585234743b956b910cf9e9342cd18b9aaea60e863413"

  strings:
    $s1 = "All your files have been encrypted " fullword wide
    $s2 = "Incorrect key" fullword wide
    $s3 = "WRONG KEY" fullword wide
    $s4 = "The key is correct" fullword wide
    $s5 = "your photos, Video, And Decomment" fullword wide
    $s6 = "To decrypt contact \"S" fullword wide
    $s7 = "Reaming Time :" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}