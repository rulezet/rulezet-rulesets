rule _Trojan_Sysbot_Gen_Variant_Ransom_VirLock_100_25_1_Trojan_Sysbot_362 {
  meta:
    description = "datamaliciousorder - from files Trojan.Sysbot_Gen.Variant.Ransom.VirLock.100_25_1.vir, Trojan.Sysbot_Gen.Variant.Ransom.VirLock.100_26_1.vir, Trojan.Sysbot_Gen.Variant.Ransom.VirLock.100_27_1.vir, Trojan.Sysbot_Gen.Variant.Ransom.VirLock.100_28_1.vir, Trojan.Sysbot_Gen.Variant.Ransom.VirLock.100_29_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.CyZ@aepfLIm_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.CyZ@aepfLIm_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.CyZ@aG0MpWl_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "670aef27a43127c22e97e65c00f7ad135b8bbace64e9f4782daadd48fa7f574d"
    hash2       = "87f3b80d757437eced8540c0a5c41fd2639cd687cd68b8c2da2cab200e641090"
    hash3       = "6726406a51886905917999c7e8db93ee0883440f396ca9691f65b3d54e705257"
    hash4       = "2daca48692ca10c8d1ed82c5a71cf5026557787df76b100af24982713e1b5817"
    hash5       = "3983bf4ce5d6a0867c7c58049cbcf588c314598cd1c3a2b200f50fb197e66f1a"
    hash6       = "f6b0f8752f9380cf259ceba538aecfd63a660a9364602f661032fb51228a9c3b"
    hash7       = "371ce28f000f4757b15503f3873e5918e19a9bafd5d9267ffe45f18258ce88b4"
    hash8       = "ca59d938f9ea07fa495eccf0b5430909139cf4131015a0c75f6e6faef1888de9"

  strings:
    $s1  = "POST /pro1.asp HTTP/1.1" fullword ascii
    $s2  = "C:\\Program Files\\Common Files\\Apple\\Mobile Device Support" fullword ascii
    $s3  = "Host:exeinfo1.org" fullword ascii
    $s4  = "version %d.%d %s (Build %d)/n" fullword ascii
    $s5  = "<description><![CDATA[" fullword ascii
    $s6  = "send is error" fullword ascii
    $s7  = "%s (Build %d)/n" fullword ascii
    $s8  = "if exist \"%s\" goto 1" fullword ascii
    $s9  = "socket Error" fullword ascii
    $s10 = "connect Error" fullword ascii
    $s11 = "Server%20" fullword ascii
    $s12 = "Personal%20" fullword ascii
    $s13 = "Professional%20" fullword ascii
    $s14 = "Advanced Server%20" fullword ascii
    $s15 = "Advanced%20Server%20" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}