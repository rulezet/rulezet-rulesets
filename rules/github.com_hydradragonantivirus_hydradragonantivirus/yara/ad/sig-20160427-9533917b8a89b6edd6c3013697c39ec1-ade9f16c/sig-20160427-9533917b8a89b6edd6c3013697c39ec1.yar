rule sig_20160427_9533917b8a89b6edd6c3013697c39ec1 {
  meta:
    description = "datamaliciousorder - file 20160427_9533917b8a89b6edd6c3013697c39ec1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cee44e26cc423c29e5d306213ae4dc943ee11a7e2ac9a50738f0925ea7c0dde2"

  strings:
    $s1  = "    return LJx + nSs + xOrKJxat + mgxBO + jnRxmLJ + wsPyG;" fullword ascii
    $s2  = "switch(0) {" fullword ascii
    $s3  = " if(5 == false) {" fullword ascii
    $s4  = "switch(3) {" fullword ascii
    $s5  = " if(7 == true) {" fullword ascii
    $s6  = " if(2 == false) {" fullword ascii
    $s7  = " if(7 == false) {" fullword ascii
    $s8  = " if(6 === false) {" fullword ascii
    $s9  = "switch(false) {" fullword ascii
    $s10 = " if(4 === false) {" fullword ascii
    $s11 = "}switch(0) {" fullword ascii
    $s12 = " if(1 === false) {" fullword ascii
    $s13 = " if(fFdqlD == false) {" fullword ascii
    $s14 = " var dBIGrWU = true; " fullword ascii
    $s15 = "  var lmtK = true; " fullword ascii
    $s16 = "function UQE () {" fullword ascii
    $s17 = " if(pMffWJj === true) {" fullword ascii
    $s18 = "function DiRds () {" fullword ascii
    $s19 = "  var clgjJrm = true; " fullword ascii
    $s20 = "}function jLWxL (wBJsv) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}