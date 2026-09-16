rule sig_20160427_45b7a7ccc741771787646deac222ac35 {
  meta:
    description = "datamaliciousorder - file 20160427_45b7a7ccc741771787646deac222ac35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "451a5087f2db3cb3faa758ed204f43efd6e126617303b8675288686e124fc38c"

  strings:
    $s1  = "switch(0) {" fullword ascii
    $s2  = "}switch(false) {" fullword ascii
    $s3  = " if(4 == false) {" fullword ascii
    $s4  = " if(5 == true) {" fullword ascii
    $s5  = " if(7 == false) {" fullword ascii
    $s6  = "switch(4) {" fullword ascii
    $s7  = "switch(false) {" fullword ascii
    $s8  = "}switch(0) {" fullword ascii
    $s9  = "  var ypY = false; " fullword ascii
    $s10 = " if(HJLkQpC === true) {" fullword ascii
    $s11 = " var XVRc = true; " fullword ascii
    $s12 = "  var NVuP = false; " fullword ascii
    $s13 = " if(omLnhXu == false) {" fullword ascii
    $s14 = "}return true;}function DNOYfU (ETUVF) {" fullword ascii
    $s15 = "  var grmWhZN = true; " fullword ascii
    $s16 = " var ldBoJnk = false; " fullword ascii
    $s17 = "}}function MtiH (uKGEKM,kvu,Hkk) {" fullword ascii
    $s18 = " var vzLrYEy = false; " fullword ascii
    $s19 = "function tar ( lfdd, lgldr, kfkm ) {" fullword ascii
    $s20 = " var wTQ = false; " fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}