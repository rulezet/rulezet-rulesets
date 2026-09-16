rule _20160802_a90af12495d6fee64dfe06df177938f6_20160802_c92deea430ad_668 {
  meta:
    description = "datamaliciousorder - from files 20160802_a90af12495d6fee64dfe06df177938f6.js, 20160802_c92deea430adb1fc85986a38d749b04d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ccc547637390a054371b093890429b09d97f1110b4a7bc5b98a84f0fa47e6f9f"
    hash2       = "da502e43bec711ce5b3f5a9b695fb435db9e2108c1f00d12f9ff63df2bc0b330"

  strings:
    $s1 = "pons\" + \"\";\\x0d\\x0avar ZW\\x6c = \"Res\" + \"\";\\x0d\\nvar Ub = \"wr\\x69te\" + \"\";\\r\\x0af\\x75nction BAn\\x28Xz3){ret" ascii
    $s2 = "{return Tl8;};var Xe1 = \"h\" + \\x22\";\\r\\nvar Lm = \"pus\"\\x20\\x2b\\x20\"\\x22;\\r\\nvar Rt =\\x20\"At\" +\\x20\"\";\\r\\n" ascii
    $s3 = "gt\" + \"\";\\r\\nfunction Qg(Bt4){retur\\x6e Bt4\\x3b};var Oi0 = \"G\\x45\\x54\" + \"\\x22;\\x0d\\nfunc\\x74ion Hg0(Ww){return " ascii
    $s4 = ";var \\x56v = \"O\" + \\x22\"\\x3b\\r\\nf\\x75nction\\x20Vr\\x33(\\x50z8){return Pz8;};var Vj\\x20= \"D\" + \"\";\\r\\nvar Oe3 =" ascii
    $s5 = "''+'nction TTv(Yk){return Yk;};va\\x72 HX\\x62 = \"send\" \\x2b \\x22\";\\x0d\\nvar E\\x51k9 = \"\\x68\" \\x2b \"\";\\r\\nvar LF" ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}