rule sig_20170315_a619b6a40c3be963562cbf54e36b45db {
  meta:
    description = "datamaliciousorder - file 20170315_a619b6a40c3be963562cbf54e36b45db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9917861f3cc6ec0bdb89a7e32f44e2067f13b0e36d41a8b22ebd5b67331f3b0"

  strings:
    $s1  = "udfupywbo1 = this[ykquwwynj(NaN) + emorpesx(NaN) + xlarxymv(NaN)];" fullword ascii
    $s2  = "sqymzu = function (comva) {" fullword ascii
    $s3  = "return ercomwoqv[0];" fullword ascii
    $s4  = "opmejdynh = function (apwiqavw) {" fullword ascii
    $s5  = "isib = function (otujg) {" fullword ascii
    $s6  = "ndagfo = function (doci) {" fullword ascii
    $s7  = "edtot = function (ojlesl) {" fullword ascii
    $s8  = "xlarxymv = function (etbire) {" fullword ascii
    $s9  = "midi = function (tvonuv) {" fullword ascii
    $s10 = "return cihurdy[0];" fullword ascii
    $s11 = "hevso = function (uqifc) {" fullword ascii
    $s12 = "adcenw = function (ufilpy) {" fullword ascii
    $s13 = "return huneh[0];" fullword ascii
    $s14 = "yskidnu = function (ysdapmelb) {" fullword ascii
    $s15 = "return apevbyv[0];" fullword ascii
    $s16 = "jylty = function (oqil) {" fullword ascii
    $s17 = "ymkoxlil = function (kreru) {" fullword ascii
    $s18 = "return egqix[0];" fullword ascii
    $s19 = "return obur[0];" fullword ascii
    $s20 = "return axokciwp[0];" fullword ascii

  condition:
    uint16(0) == 0x726f and
    8 of them
}