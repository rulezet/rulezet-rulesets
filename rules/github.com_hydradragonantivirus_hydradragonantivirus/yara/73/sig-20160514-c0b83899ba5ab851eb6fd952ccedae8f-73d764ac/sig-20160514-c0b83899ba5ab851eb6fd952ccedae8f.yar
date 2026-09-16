rule sig_20160514_c0b83899ba5ab851eb6fd952ccedae8f {
  meta:
    description = "datamaliciousorder - file 20160514_c0b83899ba5ab851eb6fd952ccedae8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e0b745de5fff82506c50db326c5db37a8ce212b75db045721c52215ae7551ac"

  strings:
    $s1  = "while (HwhCUply < UeKi - (9180 - 9178)) {" fullword ascii
    $s2  = "function GXS() {" fullword ascii
    $s3  = "function JeYxeFb(rtwjdld, kdkndmd) {" fullword ascii
    $s4  = "function peUDv() {" fullword ascii
    $s5  = "function Kenrt(VsQyrVEM) {" fullword ascii
    $s6  = "function WlOvD(UKaBTKwS) {" fullword ascii
    $s7  = "function qOoB() {" fullword ascii
    $s8  = "function JOhlDju(UHJUCDF) {" fullword ascii
    $s9  = "return JEvV;" fullword ascii
    $s10 = "YFdiO = true;" fullword ascii
    $s11 = "return RzgwFjT;" fullword ascii
    $s12 = "return cnktZzvf;" fullword ascii
    $s13 = "function Gynnv() {" fullword ascii
    $s14 = "return ilIyDS;" fullword ascii
    $s15 = "function wsjzA() {" fullword ascii
    $s16 = "function AzwKphv(qWBl, jCwJkAkJ) {" fullword ascii
    $s17 = "return YmObhFzV;" fullword ascii
    $s18 = "function flIPoa(dfegg) {" fullword ascii
    $s19 = "function KISOt() {" fullword ascii
    $s20 = "function vBjQLLp(zlWNXZbq) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}