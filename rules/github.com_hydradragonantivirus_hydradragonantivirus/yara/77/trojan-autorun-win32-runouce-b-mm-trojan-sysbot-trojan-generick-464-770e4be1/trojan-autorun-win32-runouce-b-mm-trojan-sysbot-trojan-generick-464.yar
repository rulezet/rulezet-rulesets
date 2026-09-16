rule _Trojan_Autorun_Win32_Runouce_B_mm_Trojan_Sysbot_Trojan_GenericK_464 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Win32.Runouce.B@mm.vir, Trojan.Sysbot_Trojan.GenericKDZ.104643_20.vir, Trojan.Sysbot_Trojan.GenericKDZ.104643_24.vir, Trojan.Sysbot_Trojan.GenericKDZ.104643_31.vir, Trojan.Sysbot_Trojan.GenericKDZ.104643_43.vir, Trojan.Sysbot_Trojan.GenericKDZ.104643_47.vir, Trojan.Sysbot_Trojan.GenericKDZ.104643_61.vir, Trojan.Sysbot_Trojan.GenericKDZ.104643_66.vir, Trojan.Sysbot_Trojan.GenericKDZ.104643_86.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_57_2.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_58_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e2b27b6ae78f24e07ba3f5efc3334909169fc387deca9370e0920e446d39eac"
    hash2       = "4e1e52eb5e5c8cc9a036649f7cf7e47f20f386af67ed090eb0cf709822dfafb7"
    hash3       = "21911d0fa7798c6afaf80181160ec2b0da231fcd937d1a62a906ccdcb82a2aa2"
    hash4       = "fe7c3c39ca9f6fa08130bd82d56ccd078ee054d2501eda055d8f391cf0d423e7"
    hash5       = "63f1e5ddb788f3ed3f18ff6ec0605881414d86da1863a4c83b221080a7d92a91"
    hash6       = "5a23f024530bfdd383ecce11809e61c115d29bab1fe4c0c5ca49f7866b305ee0"
    hash7       = "0fc85ee209a1b6ab8482caf65a296839e6150388a35fc457aeebd27660d22401"
    hash8       = "8aff754a86ccda10224bd82f9ae5461103b7d7f63371398cbba7f69782d5b87e"
    hash9       = "172d90a84c7575e72447e2936d7365a365af8f33bd9f4ade9aa10c406739157b"
    hash10      = "44f882c249ca30d4424fae2de9230118af48ceaec0a5a9b5f54b9de0e6c15893"
    hash11      = "71c91382da075c4bdb9a65964a6f995649ef158c507d3ea0bf2b72f21484c990"

  strings:
    $s1 = "FROM: %s@yahoo.com" fullword ascii
    $s2 = "<html><script language=\"JavaScript\">window.open(\"readme.eml\", null,\"resizable=no,top=6000,left=6000\")</script></html>" fullword ascii
    $s3 = "<html><HEAD></HEAD><body bgColor=3D#ffffff><iframe src=3Dcid:THE-CID height=3D0 width=3D0></iframe></body></html>" fullword ascii
    $s4 = "SUBJECT: %s is comming!" fullword ascii
    $s5 = "Net Send * My god! Some one killed ChineseHacker-2 Monitor" fullword ascii
    $s6 = "MAIL FROM: imissyou@btamail.net.cn" fullword ascii
    $s7 = "--#BOUNDARY#" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}