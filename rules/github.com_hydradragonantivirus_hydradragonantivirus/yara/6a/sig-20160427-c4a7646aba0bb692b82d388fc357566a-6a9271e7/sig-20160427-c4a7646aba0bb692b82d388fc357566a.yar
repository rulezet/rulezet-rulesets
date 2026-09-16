rule sig_20160427_c4a7646aba0bb692b82d388fc357566a {
  meta:
    description = "datamaliciousorder - file 20160427_c4a7646aba0bb692b82d388fc357566a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ac1a8d8fce2f6551f9cf725d414c5dfd577cf19e4fead71cb3e12c64f1fd896"

  strings:
    $s1  = " if(7 === true) {" fullword ascii
    $s2  = "switch(3) {" fullword ascii
    $s3  = " if(2 == false) {" fullword ascii
    $s4  = " if(7 == false) {" fullword ascii
    $s5  = "}switch(5) {" fullword ascii
    $s6  = "switch(5) {" fullword ascii
    $s7  = "function UrIHyG (rAeKDTqa) {" fullword ascii
    $s8  = " var dxvA = false; " fullword ascii
    $s9  = "}function kEwpvJ (TxeisD,aBIl,dfmz) {" fullword ascii
    $s10 = "function eWMgX () {" fullword ascii
    $s11 = "function sjd () {" fullword ascii
    $s12 = "function glQwtk (tog,gfyPJ) {" fullword ascii
    $s13 = " var MUCFq = false; " fullword ascii
    $s14 = " var cnDcS = true; " fullword ascii
    $s15 = " var JgpUv = true; " fullword ascii
    $s16 = " var mDKVi = false; " fullword ascii
    $s17 = " if(XwLlgss === false) {" fullword ascii
    $s18 = "switch(dfmz) {" fullword ascii
    $s19 = "function UnFdqq () {" fullword ascii
    $s20 = "function wEjWvU () {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}