rule sig_20160514_ecc29b936246ddbcecfdf78440c49b8c {
  meta:
    description = "datamaliciousorder - file 20160514_ecc29b936246ddbcecfdf78440c49b8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f0568bff05a494f5cac55cb91c31c953d78c433298920ffc5ea3f973589da5d"

  strings:
    $s1  = "while (vuJKBE < JovONGT - (4961 + 2489 - 7448)) {" fullword ascii
    $s2  = "var KmJEZos = WySS + BUn(\"033051057054\");" fullword ascii
    $s3  = "return AvOT;" fullword ascii
    $s4  = "function POtEGI() {" fullword ascii
    $s5  = "return MGqF;" fullword ascii
    $s6  = "return QKMrFZx;" fullword ascii
    $s7  = "function QgQMjK() {" fullword ascii
    $s8  = "return injHHX;" fullword ascii
    $s9  = "function UuShUL() {" fullword ascii
    $s10 = "function pjE(lfw, daQqsUn) {" fullword ascii
    $s11 = "return ZfHItIfs;" fullword ascii
    $s12 = "function SfS(muG, KpAXEd) {" fullword ascii
    $s13 = "return frrZAL;" fullword ascii
    $s14 = "return eSrCo;" fullword ascii
    $s15 = "function BUn(ejf) {" fullword ascii
    $s16 = "return iFhJALp;" fullword ascii
    $s17 = "return XktfyCNf;" fullword ascii
    $s18 = "function VaFGKPS() {" fullword ascii
    $s19 = "function LIsX() {" fullword ascii
    $s20 = "function KLKjlEv() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}