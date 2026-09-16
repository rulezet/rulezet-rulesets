rule sig_20160303_e17d359350cf84cbb985c8af4615d763 {
  meta:
    description = "datamaliciousorder - file 20160303_e17d359350cf84cbb985c8af4615d763.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c11d006c2583acf5515df6c660b9d5674b631b366f1641c68785d92865f8618c"

  strings:
    $s1  = "var zqoke = \"IwWMxO mVs pt.Shell mBvWheD Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return HdWYsYo[0] + HdWYsYo[2] + HdWYsYo[4] + \".F\" + HdWYsYo[7] + HdWYsYo[9] + HdWYsYo[12] + HdWYsYo[14];" fullword ascii
    $s3  = "var npn = (fdZ + \"TTP\" + \" xOtQENa ejNwI XML ream St AetaCdjl AD eIyJPWG OD\").split(\" \");" fullword ascii
    $s4  = "var kl = true  , zUUr = npn[7] + \"\" + npn[9];" fullword ascii
    $s5  = "HLokc.open(FCGBw,DIRvn,false);" fullword ascii
    $s6  = "var HdWYsYo = \"Sc pbrnxib r mvkkgXaZL ipting uubAUcM lwL ile VZJLmorrrpVann System gX Mouof Obj eKVtAw ect JtLAQlz\".split(\" " ascii
    $s7  = "return Hq.ExpandEnvironmentStrings(zqoke[6]);" fullword ascii
    $s8  = "function DWxZJpGVz(jkmgdqpTMcP) {" fullword ascii
    $s9  = "return WLaNy;" fullword ascii
    $s10 = "function wjFcPhpXj(TqUAA,OolRT,MSWCd) {" fullword ascii
    $s11 = "function AyHE(UrlHD) {" fullword ascii
    $s12 = "return new ActiveXObject(XuzQPg);" fullword ascii
    $s13 = "function qrJI(LLfws) {" fullword ascii
    $s14 = "if(C>=m.length) {break;}" fullword ascii
    $s15 = "function aJDW(dWTEh) {" fullword ascii
    $s16 = "return gyoDytI" fullword ascii
    $s17 = "function tbUMzma(SLRW) {" fullword ascii
    $s18 = "function OMxS(JojyT,osyVp) {" fullword ascii
    $s19 = "if (LLfws > 199011-619){return true;} else {return false;}" fullword ascii
    $s20 = "function JFbM(HLokc,DIRvn,FCGBw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}