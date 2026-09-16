rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_amBwvTb_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@amBwvTb_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b72b1ef181fbb844dbe655508744a98b997d74c8deb9c4996de051c767fda47"

  strings:
    $s1 = "kernel)V" fullword ascii
    $s2 = "ith delay %d6" fullword ascii
    $s3 = "leep)Creat+BAlloc`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}