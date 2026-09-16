rule sig_20160513_15142f39b68dd6694f363cd1ed2a7464 {
  meta:
    description = "datamaliciousorder - file 20160513_15142f39b68dd6694f363cd1ed2a7464.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2486bbe48f308653ebc11eb172f0a403a7ea96b1590addfceeb18d029ad6d44a"

  strings:
    $s1  = "while (htctbI < KFXyzTu - (3990 - 3988)) {" fullword ascii
    $s2  = "return mRxL;" fullword ascii
    $s3  = "function peefAUt() {" fullword ascii
    $s4  = "return YElHGi;" fullword ascii
    $s5  = "function NcXqm() {" fullword ascii
    $s6  = "return itijfX;" fullword ascii
    $s7  = "function ccx(tuiyo, fmmd, kemn) {" fullword ascii
    $s8  = "return LKVgOxui;" fullword ascii
    $s9  = "function vJvvFRg() {" fullword ascii
    $s10 = "function IhubNzZ(yiVRWv, OTIygoz) {" fullword ascii
    $s11 = "if (iCelfn === false) {" fullword ascii
    $s12 = "function zQrAERA(eDr) {" fullword ascii
    $s13 = "function sdmKIgu() {" fullword ascii
    $s14 = "function sJTofg(rtwjdld, kdkndmd) {" fullword ascii
    $s15 = "WwKtAX = true;" fullword ascii
    $s16 = "function xTrpZq() {" fullword ascii
    $s17 = "return ZcYJP;" fullword ascii
    $s18 = "return eyJFlSGm;" fullword ascii
    $s19 = "function YITH() {" fullword ascii
    $s20 = "function dgyzt() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}