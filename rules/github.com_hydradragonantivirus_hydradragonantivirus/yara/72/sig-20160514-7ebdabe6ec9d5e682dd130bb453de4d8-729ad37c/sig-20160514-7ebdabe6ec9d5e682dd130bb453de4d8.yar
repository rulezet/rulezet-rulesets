rule sig_20160514_7ebdabe6ec9d5e682dd130bb453de4d8 {
  meta:
    description = "datamaliciousorder - file 20160514_7ebdabe6ec9d5e682dd130bb453de4d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bee414a4ce22a7b8f2bc4b53a30318dde8e66380392efc59c6dcc4dc5f20f12"

  strings:
    $s1  = "while (lLvfn < fveSclj - (1024 + 2060 - 3082)) {" fullword ascii
    $s2  = "return WXChYOZ;" fullword ascii
    $s3  = "return WdOFMsV;" fullword ascii
    $s4  = "function jEH(ZpxMkv) {" fullword ascii
    $s5  = "function hewWi() {" fullword ascii
    $s6  = "function bdm() {" fullword ascii
    $s7  = "return uatugW;" fullword ascii
    $s8  = "return VDnfxKPD;" fullword ascii
    $s9  = "function vlKbVFG() {" fullword ascii
    $s10 = "function ZgR() {" fullword ascii
    $s11 = "function sjZcV(efouvzm) {" fullword ascii
    $s12 = "switch (\"jMsu\") {" fullword ascii
    $s13 = "return EqRbePa[ZpxMkv];" fullword ascii
    $s14 = "return XRxUgz;" fullword ascii
    $s15 = "return bUBwiE;" fullword ascii
    $s16 = "return GJzgOLpq;" fullword ascii
    $s17 = "eSFPU = true;" fullword ascii
    $s18 = "function cFEz(rtwjdld, kdkndmd) {" fullword ascii
    $s19 = "return jmWhI;" fullword ascii
    $s20 = "function wAnrOj() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}