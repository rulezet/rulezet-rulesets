rule _Trojan_Autorun_Trojan_GenericKDZ_94847_158_1_Trojan_Autorun_Tro_415 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.94847_158_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_250_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_274_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_351_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_371_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_455_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_473_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_47_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_80_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_90_1.vir, Trojan.Autorun_Trojan.Ransom.Doboc.A_1_1.vir, Trojan.Autorun_Trojan.Ransom.Doboc.A_6_1.vir, Trojan.Danger_Dump.Generic.Dacic.1A48D031.A.3287DE35_1.vir, Trojan.Danger_Gen.Trojan.FileInfector.quZ@aKGCosb_1.vir, Trojan.Danger_Gen.Trojan.Heur.duZ@HPIO3zfb_3.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_2_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_55_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_63_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_139_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_171_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_193_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_213_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_267_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_287_1.vir, Virus.Danger_Gen.Trojan.ShellObject.s8Z@aGRF3ml.vir, Virus.Hijack_Backdoor.Hangup.B_282_1.vir, Virus.Hijack_Backdoor.Hangup.B_287_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGRF3ml.vir, Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGRF3ml_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml.vir, Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml_10.vir, Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml_11.vir, Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml_12.vir, Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml_6.vir, Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml_7.vir, Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml_8.vir, Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aGRF3ml_9.vir, Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aO@sVhl.vir, Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aO@sVhl_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aO@sVhl_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aO@sVhl_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aO@sVhl_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aO@sVhl_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aO@sVhl_6.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@aO@sVhl_11.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@aO@sVhl_14.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@aO@sVhl_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@aO@sVhl_6.vir, Virus.Hijack_Gen.Trojan.ShellObject.yyZ@aO@sVhl_8.vir, Virus.Hijack_Trojan.Agent.DQQO_124.vir, Virus.Hijack_Trojan.Agent.DQQO_20.vir, Virus.Hijack_Trojan.Agent.DQQO_228.vir, Virus.Hijack_Trojan.Agent.DQQO_272.vir, Virus.Hijack_Trojan.Agent.DQQO_318.vir, Virus.Hijack_Trojan.Agent.DQQO_328.vir, Virus.Hijack_Trojan.Agent.DQQO_379.vir, Virus.Hijack_Trojan.Agent.DQQO_406.vir, Virus.Hijack_Trojan.Agent.DQQO_429.vir, Virus.Hijack_Trojan.Agent.DQQO_57.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fa279ed18d61b345262dcb846683a4a05b3ec06555a1c0208acb7128662a1c3"
    hash2       = "fecf4c746138b4667e988a88a54e7cf0c7ca37f266dbe1621cc783621c7747e1"
    hash3       = "5ba0d2256ec757341c102104318b3b0ad52e17812d2bbe1132bec0a8db2e0a2d"
    hash4       = "72daeb1ec7398848c1666db7e5e68b99f96c873199facb33a9be1ce632b5fdf4"
    hash5       = "222e338f331c2c7d8ba279ff8e46289ab655fbfc65f4336bb88824cf2e65f5e5"
    hash6       = "3e277a38abf864b096c9a64bfa9d55902ea7f53b4ed3f51cf82662ef5f46d337"
    hash7       = "95a3873d414abdf5a3d0ede4bb9dcd520031adcb77263668d68edbd88a5145b0"
    hash8       = "e17754fac81881dda6841fa26f7ad16127fe909a4b528bd05019e7f32f4b8c81"
    hash9       = "2b49d97af0a62d766d6579ed08d691ef2409613b767e8b0f9e71cc3d86a377f2"
    hash10      = "e66747fb07ee5302484d18d797a075b3eddc30fbab4d35a6f14be7bc666a7773"
    hash11      = "3dbd22b62800bac31e8f74aca201a25514adb19d4b188c65939c1e690f799345"
    hash12      = "d2fff9a8996c264c2d711a1bbd1a8581689689b4c2c47ab703f3a127654f4b57"
    hash13      = "f85fde715c2f7efa246eb815b8c2af0949e9a0f243d60a0add165eb1a6f6e3fb"
    hash14      = "53aa3fcfdd395861ea81e77e1358f1f2ebb590c1aa477823cae3239c3118139d"
    hash15      = "2066b7c5a529e5ec76db890016cbbd0bdc15e17428392b947af5fdd5e0b8b242"
    hash16      = "70cb304bf3eecde3bad70adcdbc73724ae0c59fecd2009de4adf2107a3989bca"
    hash17      = "32da20870b2e8dd6975a3b8f8af344aa8d3f3d8ea1138dd960a2831e86565823"
    hash18      = "9cda9b8f60d9c182694b843700e0422895cf94a2820e2b0439b884d4c8b2bb4b"
    hash19      = "dbb610eedff30be6f393350821bb0ebc2afdb5c8349bec912213bc3ff86f399d"
    hash20      = "4824d371d906ba83652d10f3c1e100ff161adf69f0d5227a8fccc1574de1d359"
    hash21      = "9e8f78f93f440634a9138c5e89b7832e096205874ef81f5c2e1d239c68d8e5bd"
    hash22      = "8fec92e20b34b2cde018c6300ece00253b768bea2b59d84fb3aed0114bd12546"
    hash23      = "72cedcff00198e79fba15c5ac0730a80b9ff1b6db94f60489fd241e8c8fd87cd"
    hash24      = "fcbeef759e63db04c67bbad024490b527afd2f159bf60d63fb3db37afcab1c85"
    hash25      = "57bb1161710c664e4ec4d6e164fca2ac75a59b00b99240b7825891b812edc2d3"
    hash26      = "bc14ce362462eecf4f5f2121d444475d8c410ec940f79885f519aecfb0a2154c"
    hash27      = "012c488ab987efe901b83cd9790a0cbc9faa756274731d4beb455337d3415130"
    hash28      = "475b05722d14c0baad338452a5ab74bd65c19f1d9ef705ebc2d39fa69ac61a57"
    hash29      = "5729411325d856b4ba15012614123ec3410fc4fa40dec1b4a1a3f49ec6155a87"
    hash30      = "a0c354f39a93f8625bd74a33b2a432f0ad8fdf7dff5c3422b78e97f3c16bc54b"
    hash31      = "aa594f70a8d91803d89d98a8a2615caee3dc4e68066db5059dfa5ae6e8e9598f"
    hash32      = "b6f5ea22d69d0b9b927fa0a042387e1c42e9194e3b6e31f8c102415d8dc54562"
    hash33      = "1d739697dd4d60c9867b0dd653284f44dfe0ac18ef55ab7631c39836a31ac745"
    hash34      = "5ff58266c1782b39a9bed08c660fb24227b72a8bbfbbc4c0cd27075c5b2c99a4"
    hash35      = "ad0016ec986db765d2ac1c408db7eeb3e0caf3c5bd2c5ee8fc8e10c912576eb2"
    hash36      = "c3aeee1821571cf3b37e3af33870ac6a0b9445f9067f16592a7f4103201018e3"
    hash37      = "eeed9686bd5b0fa7f914463fb23077fe54400a3b73b56e0f87bc37116748ae6c"
    hash38      = "871aa7aceeb1e635b298a5a277dd41e5c5942fa20620229d18bdba7d14767805"
    hash39      = "6aa7a856c1a0cb760282e00435c9209ed90131da348d80c8bcb4e6e8e7f8a0a8"
    hash40      = "2834c7c36da94680e57085ff112cac1dbb2855fee64135ab2e4d8aab69ab0bed"
    hash41      = "0b6e4a9372099b54ced216dea2308f3a39f14f266077e5e290086ec07c4ad00a"
    hash42      = "a5b6104a840359a418c328e87fd057e103192689d4b4ba56575070bebf120cf5"
    hash43      = "1db84549e2d7d3ba8b0a79b62332081184f29912e820f2e96db4d4b222d6a1b8"
    hash44      = "2f03ca9e74180c9a6d3a2b31affcbe3adec0b62b17a90e0b80696de353d12768"
    hash45      = "8ff3aea31a952c685c92b0d1ebeb7550749fab041f0ac3b2285e3b374acdd55f"
    hash46      = "516b2d819d8641bda164910ee363c2a264b281052587af999fdce0f587889074"
    hash47      = "0603a88f9b54a6000709f719eb270bf40aa6483831dd554a4033ef8e94410689"
    hash48      = "c739a557dccf1be474b34d351389966caeb03226d8186e0f94e73ff4db27a30a"
    hash49      = "f137f4d80974ef21c8a2a359b0045a620661c363a9b9ce58ac605be09361cf8d"
    hash50      = "0f8e8beb166fda08106dfe61d804c7eb516dda05d9f27a5ec43f047fb596fbcc"
    hash51      = "df51a543246cda0607542faf439bb5b9a16e1efe35168412c4d65bf3c11e7ccf"
    hash52      = "314d54b64d0806dfd8871c6a883f010eaf3b0bacb3eed92f721735fb30a48b48"
    hash53      = "3fd1d5667059d39b8f366d130ebf9a614bdfe16a9d300be96f6324b16ef3498d"
    hash54      = "bcb4d04de55e089bbd6c4f90265ad87ee6363445678338e913a86c2322535bc3"
    hash55      = "75ddc2e0100bdf5ecad4cffad9447b512fefa843a545ac51d56626de721f9df7"
    hash56      = "a4ddaa95745d7730016036df66db02b19046da2f3e1541bd9f1ff3015fad9259"
    hash57      = "7cbc77e83dd1c2608eda56d4e71411afc9ce1be3ecb8ef6609f4e91cf9f643f1"
    hash58      = "255a43125694cb9da930d8508ab4f45895f07f0b42e1963ff56402baa3b817d2"
    hash59      = "596fbcaa71e7c98fc399da1e52ab7111c02de5c717966946acd63f6acc83e9c4"
    hash60      = "5d41d8cda366535b36a2e448757ab880d2162b131f361967992f0f116941ba83"
    hash61      = "b2068e83781e5847c7ed523d6a1b38ca94b6c265b6ee6e52815321231f19f832"
    hash62      = "c60311ec2d9fa41c3a88140ae453e8d2b087ff0bcc3b03232734fc0c00d48e08"
    hash63      = "7bb98e1670be19cba8727481802dfc5421cbc2dfa8a63886556735fc16ed0a2d"
    hash64      = "2486510e7ffb7b658b8883feab36302ce6a141110ed2984d17233d526daf2521"

  strings:
    $s1 = "action://syncworker/startSync?entityType=%s&syncKind=%d&userId=%s" fullword wide
    $s2 = "Registration already exists for sync task : %ls. Won't register again" fullword ascii
    $s3 = "Registering sync task : %ls, interval : %d mins" fullword ascii
    $s4 = "Successfully registered sync task : %ls with interval %d mins" fullword ascii
    $s5 = "action://syncworker/startSync?entityType=%s&syncKind=%d" fullword wide
    $s6 = "action://syncworker/serverChangeNotification?entityType=%s&changeKind=%d&id=%s&userId=%s" fullword wide
    $s7 = "Unknown SyncKind value %d" fullword ascii
    $s8 = "action://syncworker/serverChangeNotification?entityType=%s&changeKind=%d&id=%s" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}