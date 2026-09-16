rule sig_20161206_0b21d05ece398df261a15cf8b8fe33cf {
  meta:
    description = "datamaliciousorder - file 20161206_0b21d05ece398df261a15cf8b8fe33cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fec8201aef769944c40ce9e985ee7fead273f6efc385cedc69c41fb752f08ca6"

  strings:
    $s1  = "function uvlogo() {" fullword ascii
    $s2  = ") + side() + vyjwegqi() + amdonlehf() + xexbu()];" fullword ascii
    $s3  = "var yksybq = ['u', ibdenk() + dafsokv() + yjkevky() + ezawna() + yrive() + page(), 'vd', 'b'];" fullword ascii
    $s4  = "function ovlyfwamv() {" fullword ascii
    $s5  = "function widty() {" fullword ascii
    $s6  = "function ylhawb() {" fullword ascii
    $s7  = "function idebe() {" fullword ascii
    $s8  = "function ykuhq() {" fullword ascii
    $s9  = "function pxinla() {" fullword ascii
    $s10 = "function emfiphap() {" fullword ascii
    $s11 = "function irizy() {" fullword ascii
    $s12 = "return npyhrym;" fullword ascii
    $s13 = "function nneflutt() {" fullword ascii
    $s14 = "function unixjynr() {" fullword ascii
    $s15 = "return mirmiqy;" fullword ascii
    $s16 = "return wzykopmo;" fullword ascii
    $s17 = "function uryqi() {" fullword ascii
    $s18 = "return koga;" fullword ascii
    $s19 = "return gezenc;" fullword ascii
    $s20 = "return ejap;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}