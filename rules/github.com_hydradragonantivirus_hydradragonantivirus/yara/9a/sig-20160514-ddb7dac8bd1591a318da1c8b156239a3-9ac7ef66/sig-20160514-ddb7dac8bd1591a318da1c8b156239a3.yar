rule sig_20160514_ddb7dac8bd1591a318da1c8b156239a3 {
  meta:
    description = "datamaliciousorder - file 20160514_ddb7dac8bd1591a318da1c8b156239a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb93241f6ef204a94b41aaa22ee09f0165f80474511047046e9d2ca68244caa"

  strings:
    $s1  = "while (OMSj < gGgC - (6301 - 6299)) {" fullword ascii
    $s2  = "function ZtkjrOz(kWcYEoPF) {" fullword ascii
    $s3  = "return kKQX[TYyXrs];" fullword ascii
    $s4  = "function Piy() {" fullword ascii
    $s5  = "return qZHWcit;" fullword ascii
    $s6  = "function VTpF(CPw, zag) {" fullword ascii
    $s7  = "function mHn(rtwjdld, kdkndmd) {" fullword ascii
    $s8  = "return xYnhJ;" fullword ascii
    $s9  = "function mBNM() {" fullword ascii
    $s10 = "return ELaDo;" fullword ascii
    $s11 = "function MZNix() {" fullword ascii
    $s12 = "return dotaqCt;" fullword ascii
    $s13 = "function PYAOouy(dsULoeI, dnGSS) {" fullword ascii
    $s14 = "var YIsZor = false;" fullword ascii
    $s15 = "return jDwEcf;" fullword ascii
    $s16 = "return ZrGoeKCx;" fullword ascii
    $s17 = "return uFdPtm;" fullword ascii
    $s18 = "function fti() {" fullword ascii
    $s19 = "function LvK(xepuv, jipLLbe) {" fullword ascii
    $s20 = "function OhmxH() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}