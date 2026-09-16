rule sig_20160513_d01c601976444bdc66627290c7c4be60 {
  meta:
    description = "datamaliciousorder - file 20160513_d01c601976444bdc66627290c7c4be60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c98d5bc5b77c19634e99abd31d2e9148f79a4d6f99f58aeb17d093b3385f121"

  strings:
    $s1  = "while (NVdQIKL < DaOzH - (4205 + 1310 - 5513)) {" fullword ascii
    $s2  = "return gLogN;" fullword ascii
    $s3  = "function TXPL() {" fullword ascii
    $s4  = "var ObBZb = true;" fullword ascii
    $s5  = "return HRYjOusF;" fullword ascii
    $s6  = "return wOKTZ;" fullword ascii
    $s7  = "function vao(DliIw, kxXg) {" fullword ascii
    $s8  = "function kCMzr(rtwjdld, kdkndmd) {" fullword ascii
    $s9  = "function NxO(tuiyo, fmmd, kemn) {" fullword ascii
    $s10 = "return PlPXH;" fullword ascii
    $s11 = "function efQokNp() {" fullword ascii
    $s12 = "return RdSDrZq;" fullword ascii
    $s13 = "function Lsxb() {" fullword ascii
    $s14 = "function ngNk() {" fullword ascii
    $s15 = "function SuvaR(Mbk, ysvgMmw) {" fullword ascii
    $s16 = "return kjqvM;" fullword ascii
    $s17 = "function BbQRTx(hONR, tgITI, sPKgP, jwpmFc) {" fullword ascii
    $s18 = "function upCNjA(SjkfNkmg) {" fullword ascii
    $s19 = "if (LDnaNn === false) {" fullword ascii
    $s20 = "function Ekq() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}