rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_aqgEuSk_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aqgEuSk_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b56895ad77349d2e59946aa9abf61722715a1382e937e4176551dc285791623d"

  strings:
    $s1 = "Heme libuzevahi lipezi paxuro" fullword wide
    $s2 = "m cannot be run in DOS mode." fullword ascii
    $s3 = "!This " fullword ascii
    $s4 = "0Raju cozibubajoceje dama caviyeyo jelefuwahokeno" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}