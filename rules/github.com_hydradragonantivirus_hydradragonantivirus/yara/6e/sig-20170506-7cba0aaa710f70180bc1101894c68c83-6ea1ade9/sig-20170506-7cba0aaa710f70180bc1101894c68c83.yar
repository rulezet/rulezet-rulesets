rule sig_20170506_7cba0aaa710f70180bc1101894c68c83 {
  meta:
    description = "datamaliciousorder - file 20170506_7cba0aaa710f70180bc1101894c68c83.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7df09a48781374a5ea8d8c5cac8e1058043aaeb2bfd0a0f9935ee96a2c3416b2"

  strings:
    $s1  = "var cizcomm = typeof undefined;" fullword ascii
    $s2  = "var exeqmi = null;" fullword ascii
    $s3  = "function igysakp() {" fullword ascii
    $s4  = "return fitaqo;" fullword ascii
    $s5  = "return ihwakr;" fullword ascii
    $s6  = "var wirnegqolm = undefined;" fullword ascii
    $s7  = "var uvyvokxuk = null;" fullword ascii
    $s8  = "var anqosvyrjux = typeof undefined;" fullword ascii
    $s9  = "return ipimyz;" fullword ascii
    $s10 = "return npypi;" fullword ascii
    $s11 = "return husvot;" fullword ascii
    $s12 = "return 334;" fullword ascii
    $s13 = "var orleravyft = undefined;" fullword ascii
    $s14 = "if (olqusy == icbuj.length) break;" fullword ascii
    $s15 = "var isbahihh = typeof undefined;" fullword ascii
    $s16 = "var lduwygkose = null;" fullword ascii
    $s17 = "return ihfup;" fullword ascii
    $s18 = "if (cmuqrygyt == null) {" fullword ascii
    $s19 = "function jegviht() {" fullword ascii
    $s20 = "function ukebybpo() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}