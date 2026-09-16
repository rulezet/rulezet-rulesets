rule _Trojan_Sysbot_Gen_Variant_Ransom_VirLock_100_30_1_Virus_Hijack__89 {
  meta:
    description = "datamaliciousorder - from files Trojan.Sysbot_Gen.Variant.Ransom.VirLock.100_30_1.vir, Virus.Hijack_Backdoor.Hangup.B_64_1.vir, Virus.Hijack_Backdoor.Hangup.B_65_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_8_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_7_1.vir, Virus.Sysbot_Gen.Variant.Pykspa.1.vir, Virus.Sysbot_Gen.Variant.Pykspa.1_1.vir, Virus.Sysbot_Gen.Variant.Pykspa.1_2.vir, Virus.Sysbot_Gen.Variant.Pykspa.1_3.vir, Virus.Sysbot_Gen.Variant.Pykspa.1_4.vir, Virus.Sysbot_Gen.Variant.Pykspa.1_5.vir, Virus.Sysbot_Gen.Variant.Pykspa.1_6.vir, Virus.Sysbot_Gen.Variant.Pykspa.1_7.vir, Virus.Sysbot_Trojan.Agent.EFYN.vir, Virus.Sysbot_Trojan.AgentWDCR.JMO.vir, Virus.Sysbot_Trojan.AgentWDCR.JMO_1.vir, Virus.Sysbot_Trojan.AgentWDCR.JMO_2.vir, Virus.Sysbot_Trojan.AgentWDCR.JMO_3.vir, Virus.Sysbot_Trojan.AgentWDCR.JMO_4.vir, Virus.Sysbot_Trojan.AgentWDCR.JMO_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68a8ae04a9348f1d3f4fe4b97712c8750b2b6f3823fd14a8bef84a959bc27308"
    hash2       = "b8bb96bcec1d2960d20df3f591dc2709349a14acea30b729777471a52c166746"
    hash3       = "133b161546cb8e2aca79ef5b52b0f3fe35e3074746b7c50232a281f0ed86c673"
    hash4       = "6c58dc5f9ac5c65f2b0107bed32c5f22ed03e0d659311a84b5959c3ff1a91e33"
    hash5       = "a806a1559bba5e8a8f4cc27993ed0f421212239ebbdcee33995fd2faec1e5bb3"
    hash6       = "d4b81056011f64b15385f71fa173da668cf2f9c03f6dbe5e16636ccc3c36dc4c"
    hash7       = "9d5f576784add77e960872378f50e50ee8d7ad988ab959b211d918995b3c71bb"
    hash8       = "40dfde13854e3ee1a6ed3cd7b790c96e18ab232dcdb1ac94a3ab9a6a795d68f5"
    hash9       = "64b0edabf6213cc300564d3958460730a5492b379e78dceb6ac2acf9a265fd95"
    hash10      = "5f4d5144cd21b303ffc91c93caba57c0af6833d33f1effffa088c7bc3bbcd8bc"
    hash11      = "1db75854ec407599092f7b6c9eb9babfc3bee1dafcf103e4111c88cb333e300b"
    hash12      = "5556637a8e7ea0bd4c1afbe61a413393cc8c92c1a91c61cf55c7969a09ebca94"
    hash13      = "28b648260df85559bdff320f03ee48c17dc86528875f880054f34015080cee8e"
    hash14      = "f5b9091b1a90c911931721275cf3987918fe0816342b6e1234b064c2867627be"
    hash15      = "5caf915bd3e8aacee27c9c81cf8cf6734740b0eefe7dd560ab9e5b03cb564e3e"
    hash16      = "f21c43f8cae2b1c950f22081014e53d995ac4703b6ec2feef18840a91b7297e8"
    hash17      = "dc5f6fb6a789224bdc28b5709acf5dbd1a8eccc32d98ab2476d630bce4b020d1"
    hash18      = "b951a3a382bdd92d20c147e8ec9b6e58623b56e12c249ee8615222a2bab1e5a4"
    hash19      = "4bdad741f0277dabfc06a969c4df30ed5cf71cac53fcf4eaaa588f0e975377fa"
    hash20      = "39a40b325d2bcb7da68626b3514386ab253ab49e186f3d8b217788720ca60791"
    hash21      = "3c9c5ba51300972a85e0b2083b59a96df3f9a57a35e4b079d743b56a726bb160"

  strings:
    $s1  = "GET USER %s HOMEPAGE" fullword ascii
    $s2  = "GET USER %s MOOD_TEXT" fullword ascii
    $s3  = "GET USER %s COUNTRY" fullword ascii
    $s4  = "GET USER %s SEX" fullword ascii
    $s5  = "GET USER %s ABOUT" fullword ascii
    $s6  = "GET USER %s LANGUAGE" fullword ascii
    $s7  = "GET USER %s PHONE_MOBILE" fullword ascii
    $s8  = "GET USER %s PHONE_HOME" fullword ascii
    $s9  = "GET USER %s ONLINESTATUS" fullword ascii
    $s10 = "GET USER %s PHONE_OFFICE" fullword ascii
    $s11 = "GET USER %s FULLNAME" fullword ascii
    $s12 = "GET USER %s ISBLOCKED" fullword ascii
    $s13 = "GET USER %s BUDDYSTATUS" fullword ascii
    $s14 = "GET USER %s CITY" fullword ascii
    $s15 = "GET USER %s BIRTHDAY" fullword ascii
    $s16 = "GET USER %s ISAUTHORIZED" fullword ascii
    $s17 = "GET MESSAGE %d TIMESTAMP" fullword ascii
    $s18 = "GET CHAT %s TIMESTAMP" fullword ascii
    $s19 = "GET MESSAGE %d PARTNER_HANDLE" fullword ascii
    $s20 = "GET CHAT %s CHATMESSAGES" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}