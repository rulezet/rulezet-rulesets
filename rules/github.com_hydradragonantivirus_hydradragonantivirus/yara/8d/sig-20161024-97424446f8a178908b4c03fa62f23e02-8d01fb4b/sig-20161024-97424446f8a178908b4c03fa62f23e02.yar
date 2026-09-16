rule sig_20161024_97424446f8a178908b4c03fa62f23e02 {
  meta:
    description = "datamaliciousorder - file 20161024_97424446f8a178908b4c03fa62f23e02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9422ed5736cf4a3fb619183d1696894845490e3642874d7c54a23bacd7fde3ff"

  strings:
    $s1  = "function binta() {" fullword ascii
    $s2  = "if (ijsyd == null) {" fullword ascii
    $s3  = "var yqoden = false;" fullword ascii
    $s4  = "var uqehejy = typeof undefined;" fullword ascii
    $s5  = "function tobezyzp() {" fullword ascii
    $s6  = "function futlunl() {" fullword ascii
    $s7  = "if (alximsaqa == null) {" fullword ascii
    $s8  = "function lucmywy() {" fullword ascii
    $s9  = "if (ubxywc() == undefined) {" fullword ascii
    $s10 = "var ypzynajeh = typeof null;" fullword ascii
    $s11 = "return ycnofsemq;" fullword ascii
    $s12 = "return lkejra;" fullword ascii
    $s13 = "function myweqgaqd() {" fullword ascii
    $s14 = "function ofume() {" fullword ascii
    $s15 = "var rykovve = null;" fullword ascii
    $s16 = "function ymvahyhi() {" fullword ascii
    $s17 = "var mcymyxocu = typeof false;" fullword ascii
    $s18 = "return ajvarzi;" fullword ascii
    $s19 = "if (zsemydj == undefined) {" fullword ascii
    $s20 = "return uwuz;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}