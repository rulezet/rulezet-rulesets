rule sig_20160427_b7728c7fe47b332a5b4507054a2d9317 {
  meta:
    description = "datamaliciousorder - file 20160427_b7728c7fe47b332a5b4507054a2d9317.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed7e81e7ced8541045e83d9ea0298a494acf9855ea568e21aff721bc0d1a41"

  strings:
    $s1  = "+ EPoS;EPoS = 22 - 7576;var lEB = 8933;var qAHFsAk = 1497;OibWYL = lEB - qAHFsAk;" fullword ascii
    $s2  = " var OibWYL = 5336;var tuLtuXX = 9224;var rlFS = 9904;OibWYL = tuLtuXX * rlFS;var FzKwYg = 1881;var EPoS = 8509;FzKwYg = OibWYL " ascii
    $s3  = " var OibWYL = 5336;var tuLtuXX = 9224;var rlFS = 9904;OibWYL = tuLtuXX * rlFS;var FzKwYg = 1881;var EPoS = 8509;FzKwYg = OibWYL " ascii
    $s4  = "switch(0) {" fullword ascii
    $s5  = " if(4 == false) {" fullword ascii
    $s6  = " if(5 == true) {" fullword ascii
    $s7  = "switch(false) {" fullword ascii
    $s8  = " var NKdH = true; " fullword ascii
    $s9  = "  var hfgC = true; " fullword ascii
    $s10 = "function bNlEJTe () {" fullword ascii
    $s11 = "function zmvEmU () {" fullword ascii
    $s12 = "}function VoTC () {" fullword ascii
    $s13 = "return false;}function acc (bJH) {" fullword ascii
    $s14 = "function XllxFkA ( dfegg ) {" fullword ascii
    $s15 = "function luIfdF () {" fullword ascii
    $s16 = " var VhgH = true; " fullword ascii
    $s17 = "function QbB () {" fullword ascii
    $s18 = " if(IsWd == false) {" fullword ascii
    $s19 = " var LWZ = false; " fullword ascii
    $s20 = " var gQhee = true; " fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}