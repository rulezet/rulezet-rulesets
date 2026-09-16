rule sig_20160514_2223966aa4f8c5bdac0e105661ad6ca7 {
  meta:
    description = "datamaliciousorder - file 20160514_2223966aa4f8c5bdac0e105661ad6ca7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55cd5afbf435d8f9bc30a5ef878b974e657bd6fc61cb0e647c814dd79bed5afd"

  strings:
    $s1  = "while (kWox < cjmk - (9892 - 9890)) {" fullword ascii
    $s2  = "function rMKcpk() {" fullword ascii
    $s3  = "function doI(tuiyo, fmmd, kemn) {" fullword ascii
    $s4  = "return neqCRkhT;" fullword ascii
    $s5  = "function pTsUuz() {" fullword ascii
    $s6  = "return OCkIWJBe;" fullword ascii
    $s7  = "switch (cJs) {" fullword ascii
    $s8  = "return twdCwyM;" fullword ascii
    $s9  = "function LGldJ() {" fullword ascii
    $s10 = "return hsfrbc;" fullword ascii
    $s11 = "if (EHVEn === false) {" fullword ascii
    $s12 = "return SxJU;" fullword ascii
    $s13 = "return benpLG;" fullword ascii
    $s14 = "function zxKZXfK() {" fullword ascii
    $s15 = "function FHLup(OveQzrD) {" fullword ascii
    $s16 = "function nTWnKq() {" fullword ascii
    $s17 = "function Hbyoob(dnN, nDbJL) {" fullword ascii
    $s18 = "function fnxLuWM() {" fullword ascii
    $s19 = "function rBaSPL(rtwjdld, kdkndmd) {" fullword ascii
    $s20 = "switch (170) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}