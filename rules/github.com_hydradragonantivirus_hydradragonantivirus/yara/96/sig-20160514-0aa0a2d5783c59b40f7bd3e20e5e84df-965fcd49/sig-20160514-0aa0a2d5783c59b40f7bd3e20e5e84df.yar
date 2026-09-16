rule sig_20160514_0aa0a2d5783c59b40f7bd3e20e5e84df {
  meta:
    description = "datamaliciousorder - file 20160514_0aa0a2d5783c59b40f7bd3e20e5e84df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7af8098f15ac7329ea980dd6f63a61d58af4a7e3724408fbb9a8852203d5cab2"

  strings:
    $s1  = "while (nstes < rCNhWij - (3149 + 2121 - 5268)) {" fullword ascii
    $s2  = "function tyhMpHD(akW) {" fullword ascii
    $s3  = "function rJO(lgPWh) {" fullword ascii
    $s4  = "var LBSVxJUZ = String;" fullword ascii
    $s5  = "var NEVe = (3626, 3950, 3539, 7740, 4530, 8297, 8855, 4805, jWi(\"054007045\"));" fullword ascii
    $s6  = "function suCqx(VasfbdqL) {" fullword ascii
    $s7  = "function mFlzX() {" fullword ascii
    $s8  = "return XcLSa;" fullword ascii
    $s9  = "ljkEmL(false);" fullword ascii
    $s10 = "DvtsbCl(sfZSBnjb, NEVe, WVTbX);" fullword ascii
    $s11 = "function cBi() {" fullword ascii
    $s12 = "function bERc() {" fullword ascii
    $s13 = "return TuXZPFq;" fullword ascii
    $s14 = "return LJiqV;" fullword ascii
    $s15 = "function ljkEmL() {" fullword ascii
    $s16 = "function oib() {" fullword ascii
    $s17 = "function tOaJlW() {" fullword ascii
    $s18 = "return UhtHZrgv;" fullword ascii
    $s19 = "function bSeAHZs() {" fullword ascii
    $s20 = "return GhmBe;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}