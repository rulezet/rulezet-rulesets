import "pe"
rule _Trojan_Hooker_Win32_Floxif_A_50_1_Trojan_Hooker_Win32_Floxif_A__334 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Win32.Floxif.A_50_1.vir, Trojan.Hooker_Win32.Floxif.A_51_1.vir, Trojan.Hooker_Win32.Floxif.A_57_1.vir, Trojan.Hooker_Win32.Floxif.A_5_1.vir, Trojan.Hooker_Win32.Floxif.A_7_1.vir, Trojan.Injector _Backdoor.Hupigon.AAAH_1.vir, Trojan.Sysbot_Trojan.VB.OJW.vir, Trojan.Sysbot_Trojan.VB.OJW_1.vir, Trojan.Sysbot_Trojan.VB.OJW_2.vir, Trojan.Sysbot_Trojan.VB.OJW_3.vir, Trojan.Sysbot_Trojan.VB.OJW_4.vir, Trojan.Sysbot_Trojan.VB.OJW_5.vir, Trojan.Sysbot_Trojan.VB.OJW_6.vir, Trojan.Sysbot_Trojan.VB.OJW_7.vir, Trojan.Sysbot_Trojan.VB.OJW_8.vir, Trojan.Sysbot_Trojan.VB.OJW_9.vir, Trojan.Sysbot_Worm.Ludbaruma.A.vir, Trojan.Sysbot_Worm.Ludbaruma.A_1.vir, Trojan.Sysbot_Worm.Ludbaruma.A_2.vir, Trojan.Sysbot_Worm.Ludbaruma.A_3.vir, Trojan.Sysbot_Worm.Ludbaruma.A_4.vir, Trojan.Sysbot_Worm.Ludbaruma.A_5.vir, Trojan.Sysbot_Worm.Ludbaruma.A_6.vir, Trojan.Sysbot_Worm.Ludbaruma.B_47.vir, Trojan.Sysbot_Worm.Ludbaruma.B_48.vir, Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8186a987cdc240fe93066d204955dc53e0da9315fe867c1f8c85154a2dfc4bd8"
    hash2       = "c6c7e4ea114bb7e7949765d69e7e1ff4cdcaeb0ee430c10200736936a7965af3"
    hash3       = "6db3a624299e459dd824db9b4e9c500cd2bfba45eeea5a7c6138640e26b0f8e6"
    hash4       = "d4053730d8d99ff4ae4b0d451c90b882c298aa641ae8281a3fad654bd617e13a"
    hash5       = "2bffa927c77af04836be00e3533830224413937f1e115ce73531886d9dec89f0"
    hash6       = "84771d49bef65af5a539c285bb5d760ac9bc4ab1a587b5921c9f774b871fdf0e"
    hash7       = "b160ad331c1f77bd46d86a61872796ef4e4131e715f996b56010dc9bfb941f79"
    hash8       = "05c5df005de57b3b013c4072c4dc28493b24ce790488a007309ce75c44bab657"
    hash9       = "ca88d8a053f7da6ec294862347830d26193a7c62d1b4015b7edf8a9f41164727"
    hash10      = "11d14530d7670db7d3375f41878e9f18134cc9c0fdf8dd1f583defb2f9334cfc"
    hash11      = "18d059eefde24ae761f6530ae3d45e139b9aa506a858416b4d07ebca060d689e"
    hash12      = "3600b4cf119a93fa453285f612d7afc13177d3540822abd6bf06ab2836884336"
    hash13      = "5d61793bdf1d0dc124cdfe4d4771deac568b0f1a896d0f8ce41ed4f080e64ccc"
    hash14      = "a122dc8c0e4831c123ccc0fe7ca590f356f697a2d0d7eede60c6aa40baee94ec"
    hash15      = "60a3853377ca4c671710d2b267b1572791fa71f0b4f2975ed07cc8916975058d"
    hash16      = "158c4359c81da02f81a38ef5bbd23c4aab0cde16e6d30a137b4ac0d520b171b5"
    hash17      = "772df26c3a2528ac06bf3ae003b402e621590e9326fb7c6e1755e764f97e2d37"
    hash18      = "31ff33cd9c692e05f71f5c75a92be000e2d7ea1c4a98611a7f7a1976f3890c73"
    hash19      = "0e9c0cd46bf765c2bfbc7f025181fba33b0c407087e2150096088b8794eaca33"
    hash20      = "1c1cea7406e23ca3588cb581eeaa19cdeb54f5fe827d71259b508fedd5f6c268"
    hash21      = "59fee67ee81ed3495388902e486e174874e46ed45f855fb09a8a3f4e9e05716f"
    hash22      = "1f987196c5e7853856d11edaf78453dce69b71fb43a3789ad681c52686bc9a65"
    hash23      = "957b59244f51a8792f0414f2dc0f8c707b688cede05a806187518b893a6b98ca"
    hash24      = "f6302f28c7fdab09e925a178e938b9c4dd31b634b6dcc0757d63153f55fb379a"
    hash25      = "1a9cc81de6a1c8171823938d22e1a47e39fea2ae5efa43f75baa1c3b06c783e9"
    hash26      = "e6b10f28c4b62c13b775cc753aabecaed274524e9431ca4a2a379832e6054707"

  strings:
    $s1 = "Ini Data yang anda minta." fullword wide
    $s2 = "Ini Data yang sangat penting Mohon di simpan ." fullword wide
    $s3 = "Apa yang aku lakukan dapat menyakitimu" fullword wide
    $s4 = "Apa yang kau lakukan takkan menyakitiku" fullword wide
    $s5 = "Berulang kali kau lakukan Tak akan aku rasakan" fullword wide
    $s6 = "Masih ada lagi yang ku kejar saat ini" fullword wide
    $s7 = "Saat ini akan ku mulai mengejar yang lain" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "135e92fc9902f3140f2e5a51458efdf0" and (all of them)
    ) or (all of them)
}