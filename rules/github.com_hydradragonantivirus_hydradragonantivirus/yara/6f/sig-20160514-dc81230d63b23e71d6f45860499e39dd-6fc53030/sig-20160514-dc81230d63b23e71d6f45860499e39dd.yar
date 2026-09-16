rule sig_20160514_dc81230d63b23e71d6f45860499e39dd {
  meta:
    description = "datamaliciousorder - file 20160514_dc81230d63b23e71d6f45860499e39dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcdd36154d6966116bed98adf5545e45b221d7cfc5dfaf9164d2b5390bc45bde"

  strings:
    $s1  = "while (MUmjLJHt < uFOcZC - (4424 - 4422)) {" fullword ascii
    $s2  = "return xccYSKYg;" fullword ascii
    $s3  = "return tNLss;" fullword ascii
    $s4  = "if (aZHhgB === false) {" fullword ascii
    $s5  = "function cGUI(NsIu, qMCGKS) {" fullword ascii
    $s6  = "return nHdU;" fullword ascii
    $s7  = "function Gkz() {" fullword ascii
    $s8  = "return ZNfli;" fullword ascii
    $s9  = "function oyYSg() {" fullword ascii
    $s10 = "return hcUtxRxx;" fullword ascii
    $s11 = "function dqNKwR(uSldmTuZ) {" fullword ascii
    $s12 = "var LERqQIX = String;" fullword ascii
    $s13 = "function dOu() {" fullword ascii
    $s14 = "function cfKOO() {" fullword ascii
    $s15 = "function fOa() {" fullword ascii
    $s16 = "var lZodC = false;" fullword ascii
    $s17 = "function lyTrBKL() {" fullword ascii
    $s18 = "function Awld() {" fullword ascii
    $s19 = "function zqI() {" fullword ascii
    $s20 = "return wbXU;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}