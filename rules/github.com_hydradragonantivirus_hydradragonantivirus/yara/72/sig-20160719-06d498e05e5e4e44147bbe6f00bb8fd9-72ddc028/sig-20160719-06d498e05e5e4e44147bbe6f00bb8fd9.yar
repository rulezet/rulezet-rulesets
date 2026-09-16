rule sig_20160719_06d498e05e5e4e44147bbe6f00bb8fd9 {
  meta:
    description = "datamaliciousorder - file 20160719_06d498e05e5e4e44147bbe6f00bb8fd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f560f570c745f3db52021635d94f97cb4d356449c59efb97cdfa4835d5c563c"

  strings:
    $s1  = "while (rmReSVec < sjokpbdQ - 2) {" fullword ascii
    $s2  = "var KzFzLO = new Array(kWlbW + \"r\" + sIeXEFS);" fullword ascii
    $s3  = "function XsEtl() {" fullword ascii
    $s4  = "function hqxGzWa(rety, serq) {" fullword ascii
    $s5  = "return Mvakbzg;" fullword ascii
    $s6  = "function UXMfnJ(ZYHnw) {" fullword ascii
    $s7  = "return WtSeW;" fullword ascii
    $s8  = "return easbbKG;" fullword ascii
    $s9  = "var UIntvw = String;" fullword ascii
    $s10 = "return ZcYbMFea;" fullword ascii
    $s11 = "function qljp(maHJUqWo, sSVaCuz) {" fullword ascii
    $s12 = "function ejdmVtS() {" fullword ascii
    $s13 = "function oFcx() {" fullword ascii
    $s14 = "var JRAzERn = false;" fullword ascii
    $s15 = "return YMWbsFaD;" fullword ascii
    $s16 = "return bIkj;" fullword ascii
    $s17 = "return yAxX;" fullword ascii
    $s18 = "function crDljP() {" fullword ascii
    $s19 = "function EeSRal(QDRIdX) {" fullword ascii
    $s20 = "return tWJlb;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}