rule sig_20170309_21da0b1b5d85ae28d30951b11665a793 {
  meta:
    description = "datamaliciousorder - file 20170309_21da0b1b5d85ae28d30951b11665a793.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6d43acd1fc327d08d2defa8d210170b3c4c6e385cdd8c55ed93da03e9654d27"

  strings:
    $s1  = "function ydax(nfigaspy) {" fullword ascii
    $s2  = "ecuti6 = this[dnenceht(1) + visev(1) + axfupko(1)];" fullword ascii
    $s3  = "function etavh(epynrunw) {" fullword ascii
    $s4  = "return tufejly[0];" fullword ascii
    $s5  = "function rfogol(tufo) {" fullword ascii
    $s6  = "function urejyp(edena) {" fullword ascii
    $s7  = "function ajjojgy(asjasgeh) {" fullword ascii
    $s8  = "var piwy = [Function, String, String, String, String, String][0];" fullword ascii
    $s9  = "return ikhamk[0];" fullword ascii
    $s10 = "return ghuhbi[0];" fullword ascii
    $s11 = "function uwemosb(nedje) {" fullword ascii
    $s12 = "function uxkexma(vyfe) {" fullword ascii
    $s13 = "function iddosm(gatucu) {" fullword ascii
    $s14 = "return styhymhe[0];" fullword ascii
    $s15 = "function cerucn(uzaz) {" fullword ascii
    $s16 = "return unixygg[0];" fullword ascii
    $s17 = "function pponterf(sjixa) {" fullword ascii
    $s18 = "function ihsef(ejaqq) {" fullword ascii
    $s19 = "function izifninf(bufa) {" fullword ascii
    $s20 = "return ykan[0];" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}