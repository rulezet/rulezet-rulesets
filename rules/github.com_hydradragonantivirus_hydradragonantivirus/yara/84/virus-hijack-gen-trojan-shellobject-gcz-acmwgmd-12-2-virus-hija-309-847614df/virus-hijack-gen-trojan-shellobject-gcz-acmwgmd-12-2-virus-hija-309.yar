rule _Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_12_2_Virus_Hija_309 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_12_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_191_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_201_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8fa34b59b89347ae6317e5dcdac2ecd93cade06002e23a9f278d65c36d4ecb3"
    hash2       = "5f3da4bd02ec2c4ff6c40fb4e5bd2306bf73bb9599e814c5263588ce783c4035"
    hash3       = "7898240223128514c4c398dfc326e36d4fa94fb54ae3519b0947af8331bbea41"
    hash4       = "a3c089ebceb0a5981e810bdc1535c1c845b1e4d09ff45be733dc8e79982433bd"

  strings:
    $s1  = "I/O Failure" fullword wide
    $s2  = "Virdian Unified Debugging Session Demuxer" fullword wide
    $s3  = "    com:port=id,baud=rate connects through a COM port" fullword ascii
    $s4  = "Starting in auotlaunch mode" fullword ascii
    $s5  = "Bad packet byte count" fullword wide
    $s6  = "Bad packet trailing byte" fullword wide
    $s7  = "Bad Mux packet type" fullword wide
    $s8  = "Bad Mux packet size" fullword wide
    $s9  = "Bad embedded packet byte count" fullword wide
    $s10 = "Bad embedded kdpacket trailing byte" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}