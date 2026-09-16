rule sig_20160428_cb4cef2c34b4e7ff89da5b53c77c9a5b {
  meta:
    description = "datamaliciousorder - file 20160428_cb4cef2c34b4e7ff89da5b53c77c9a5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c67575f1a3a9e036f98469f8c32b22aa5af61c6cccd04eca20e6644587c127a5"

  strings:
    $s1  = "while (Aygpcz < YaExC - (3009, 525, 371, 6486, 3105, 6933, 6766, 6392, 6469, 3411, 5363, 9634, 2)) {" fullword ascii
    $s2  = "return IPh + kpY + xGesH + ysIa + gWmVe + mJHmAKU;" fullword ascii
    $s3  = "if (6 === false) {" fullword ascii
    $s4  = "if (3 == true) {" fullword ascii
    $s5  = "if (6 == false) {" fullword ascii
    $s6  = "if (5 === false) {" fullword ascii
    $s7  = "if (1 === true) {" fullword ascii
    $s8  = "function hrA(dldd, lfdff) {" fullword ascii
    $s9  = "return QCwl;" fullword ascii
    $s10 = "return LAEu;" fullword ascii
    $s11 = "if (gDMrY == false) {" fullword ascii
    $s12 = "function VFFT(zSEsKXzd, PhqtSH) {" fullword ascii
    $s13 = "var vnaFZ = true;" fullword ascii
    $s14 = "if (laHQwn == true) {" fullword ascii
    $s15 = "function SOwdvM(dsnIbr) {" fullword ascii
    $s16 = "return xWO;" fullword ascii
    $s17 = "var ROiKvZk = false;;" fullword ascii
    $s18 = "function Req() {" fullword ascii
    $s19 = "function GRquWuQ() {" fullword ascii
    $s20 = "return TTH;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}