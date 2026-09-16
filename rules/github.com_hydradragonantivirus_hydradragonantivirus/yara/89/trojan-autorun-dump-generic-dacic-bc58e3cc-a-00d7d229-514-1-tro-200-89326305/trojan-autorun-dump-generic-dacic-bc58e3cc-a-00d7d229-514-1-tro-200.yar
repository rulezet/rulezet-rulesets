import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_514_1_Tro_200 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_514_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_647_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_741_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_817_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_821_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_822_1.vir, Virus.Hijack_Backdoor.Hangup.B_133.vir, Virus.Hijack_Backdoor.Hangup.B_17.vir, Virus.Hijack_Backdoor.Hangup.B_188.vir, Virus.Hijack_Backdoor.Hangup.B_218.vir, Virus.Hijack_Backdoor.Hangup.B_239.vir, Virus.Hijack_Backdoor.Hangup.B_291.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_117.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_134.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_281.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_297.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_349.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_378.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_38.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_446.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_450.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_60.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_94.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a229aeec7918a59e451540db04acadf2d188897a851cda4bc1f3f618dd6e4892"
    hash2       = "28b237097b8ba48796eb10a102ce495da63e74e1cef01e2aee9da2cd24d80726"
    hash3       = "82a954e07a08b554026ce2ef0a7b9cbb7217faf5dee479043d1f91189fa2f7dd"
    hash4       = "3e2e18af942356d7bf46adfc0c687d4e2d441549203a11f59694b81175656b1c"
    hash5       = "2a75c6712abae9753b10832e77e8093361543feadfcbf562acd45e52f88826fa"
    hash6       = "dfc315128fff6c76865c906fad9f2bf0b58624768b1eb347802ea1189b7697eb"
    hash7       = "2f991b271fdc47336633c453ba9cf54a5e5496a7988077bd87bc6bd01fbe47dc"
    hash8       = "5c71905bf0c62e356254584e330ce9aaab5c37c78305791eddbbe044ad7157b4"
    hash9       = "44686e103113a43b78c36452bd7c6324751842322f631149f181c1f2c3c0c3c3"
    hash10      = "ef4693483a8849c3e2f6ffc8a2811b44327ed840fcd42bd2b79994d2d0e59aab"
    hash11      = "388e59352f65aa43d37d1b1cd27aa518f033e80d359d0d723be6fe1f5713cfaf"
    hash12      = "01d19e0aeaf8472c014881d28c5a9d29ed4733eafa148414de1676db52e511e4"
    hash13      = "d25f7f397c85c303332bc04004d00f8936d4d3ae56e4273b1805becf0927192c"
    hash14      = "d361ddfce9af9334c2080f176c1e624c1cc9be6e48be2c7f39ba84e286df46b5"
    hash15      = "903bc692c15dec798ef54555d5a39ae41664ff45fbdb5a19fe26ebc477d933b2"
    hash16      = "976243c049672e1b9036e14b25ba8979d268f0b994e2a9db52db502c4faf9111"
    hash17      = "6c04b1f397bfce722260ec9f6097460c4aaa280b40aedfc40201bc3a269e4aa0"
    hash18      = "c027204129bef8d717be0cd3fc5a3fd81608cba9312ecbcbdd715c61c729c4f5"
    hash19      = "78e18ee598dd2f513b0e9b7b71c034413635a344fe0f5a5d928ef223e7231e95"
    hash20      = "0cdcb62a05e8a76cea8555aa3c6bfe3a9941cd30a3c84c46075a4279c1a68531"
    hash21      = "aa5ddf5456ac46fcf4e3e7207074bcc093acbfb0b4110e732634916491abe20f"
    hash22      = "68c6c40a4d9477e99005c09f427b3c027f14200f4fd19090dc55741b832684bf"
    hash23      = "8cd126e2266342b1a5ab624394134c54be516a45a80d041775b9f1f71b587e34"

  strings:
    $s1 = "cZAr}l" fullword ascii
    $s2 = "&%^,NAil&" fullword ascii
    $s3 = "+_,NAil&" fullword ascii
    $s4 = "6+_,NAil&" fullword ascii
    $s5 = "N5\\,NAil&" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "95e6f8741083e0c7d9a63d45e2472360" and (all of them)
    ) or (all of them)
}