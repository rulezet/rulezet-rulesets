rule _Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_194_2_Tro_410 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_194_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_195_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_196_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_199_2.vir, Virus.Delself_Trojan.GenericKD.38632388.vir, Virus.Delself_Trojan.GenericKD.38632388_1.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_9_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_137_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbb267b95e6f1c3639bb267d347d05a8bcf99f5b835fe605b1e86a7e7b3f857b"
    hash2       = "f973c575963c0b734123c57589e95689e1dd347e01b4aef76cf9a021a34e2e95"
    hash3       = "a49d5ee298caf7ee053ed46a206f8d8aa1abf3acfe61719798c0cf338f6a3c4f"
    hash4       = "4511810343ffe65473d950c6638c0d4e9237e7bf84d843e2c3e856bcc9cd5443"
    hash5       = "b70b8824ee319ffd7bd1c6e5ac319a3cb45f36dbb7eb5ea4d9a7a8c7b11df773"
    hash6       = "647a1b3c87218ae8531de8f198ad56c5e39b91093353bbc58f69d8086d5bfc1e"
    hash7       = "67866b2cc2c65627481090fda91056657f994fbd21ecd4e9ad258235ddd2a3ae"
    hash8       = "5b01fcd0be886fad45663b6b4aa2bcb6a6bdb4bc3c72a0264eee584d2ffda74a"

  strings:
    $s1 = "left on" fullword ascii
    $s2 = "P#include \"afx" fullword ascii
    $s3 = "Everyone:F|" fullword ascii
    $s4 = "CoInitial" fullword ascii
    $s5 = "l Preview " fullword ascii
    $s6 = "tE,tIME" fullword ascii
    $s7 = " (core" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}