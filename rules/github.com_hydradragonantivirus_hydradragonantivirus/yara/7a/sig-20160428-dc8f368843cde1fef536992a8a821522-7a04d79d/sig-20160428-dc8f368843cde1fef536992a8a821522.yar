rule sig_20160428_dc8f368843cde1fef536992a8a821522 {
  meta:
    description = "datamaliciousorder - file 20160428_dc8f368843cde1fef536992a8a821522.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d14dd34eca4b76e6c9445feffd3e886fe571e993e1437e0c2ad96365a0211e2"

  strings:
    $s1  = "while (Vhc < JTDn - (693, 3557, 4300, 2)) {" fullword ascii
    $s2  = "ymDn = KZI - ROhan;" fullword ascii
    $s3  = "ROhan = 1677 - 1145;" fullword ascii
    $s4  = "return GiRrKSZ + lUp + mOwynD + Mpo + XskhUWmI + vAUftU;" fullword ascii
    $s5  = "if (5 == false) {" fullword ascii
    $s6  = "if (2 == false) {" fullword ascii
    $s7  = "if (7 == false) {" fullword ascii
    $s8  = "if (7 === true) {" fullword ascii
    $s9  = "if (5 == true) {" fullword ascii
    $s10 = "function SaFT() {" fullword ascii
    $s11 = "Vwto(true);" fullword ascii
    $s12 = "return Ius;" fullword ascii
    $s13 = "var omlOf = true;" fullword ascii
    $s14 = "return IocVeb[SNHun];" fullword ascii
    $s15 = "return EOAf;" fullword ascii
    $s16 = "switch (\"DYxMAmSc\") {" fullword ascii
    $s17 = "function eTQGgBA() {" fullword ascii
    $s18 = "var klAOs = false;" fullword ascii
    $s19 = "return ZLnfLicL;" fullword ascii
    $s20 = "return noFMuDh;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}