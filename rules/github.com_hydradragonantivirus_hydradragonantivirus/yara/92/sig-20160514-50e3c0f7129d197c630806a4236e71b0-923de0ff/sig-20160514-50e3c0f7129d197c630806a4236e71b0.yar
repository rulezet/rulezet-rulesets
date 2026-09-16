rule sig_20160514_50e3c0f7129d197c630806a4236e71b0 {
  meta:
    description = "datamaliciousorder - file 20160514_50e3c0f7129d197c630806a4236e71b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b1436eabf4736e8d363aa3223972705cd9777ab3e759a662a63c7005e0ec88b"

  strings:
    $s1  = "while (NlwoL < DhZOMo - (7785 - 7783)) {" fullword ascii
    $s2  = "return CCsVF;" fullword ascii
    $s3  = "return mQKdXRl;" fullword ascii
    $s4  = "return pljCKWPT;" fullword ascii
    $s5  = "function HJHlPG(AQY) {" fullword ascii
    $s6  = "function BlBnp(TvVORHXH) {" fullword ascii
    $s7  = "function IQE(EgDxyml) {" fullword ascii
    $s8  = "return DVRYL;" fullword ascii
    $s9  = "function gmr() {" fullword ascii
    $s10 = "return KoLlIXRo;" fullword ascii
    $s11 = "function cgys() {" fullword ascii
    $s12 = "return MaqKLp;" fullword ascii
    $s13 = "return KeVYBZKq;" fullword ascii
    $s14 = "switch (792) {" fullword ascii
    $s15 = "function GghrbFC() {" fullword ascii
    $s16 = "return OqokIPF;" fullword ascii
    $s17 = "function rRsaMjQ() {" fullword ascii
    $s18 = "function nweMOIB(OYxhA) {" fullword ascii
    $s19 = "return AaTJXf;" fullword ascii
    $s20 = "function eQmN() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}