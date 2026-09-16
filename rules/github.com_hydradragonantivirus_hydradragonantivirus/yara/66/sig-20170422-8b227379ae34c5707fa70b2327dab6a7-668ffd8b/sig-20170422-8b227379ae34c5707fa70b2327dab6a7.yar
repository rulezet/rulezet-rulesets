rule sig_20170422_8b227379ae34c5707fa70b2327dab6a7 {
  meta:
    description = "datamaliciousorder - file 20170422_8b227379ae34c5707fa70b2327dab6a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41af1e26407357317aced26d3271c20f7c0053051c1a77c319dd8c61350e63b0"

  strings:
    $s1  = "o0OOOO0=(new Function(\"O0OOoOo\",\"oo0O0o0\",\"oo00o00=/\\\\S{1}/g;return O0OOoOo[oo0O0o0](oo00o00);\")(oOo00o0,new Array(1,\"m" ascii
    $s2  = "oO0oOOo=(new Function(\"Oo0ooo0\",\"ooOOO0o\",\"var ooooOO0=new Array(167,163,31,148,120,28,46,89,23,155,196,38,107,72,125,227)," ascii
    $s3  = "function o0Oo0oo(OOOoOOo,o0OoooO)" fullword ascii
    $s4  = "return o0OOOO0;" fullword ascii
    $s5  = "return oO0oOOo;" fullword ascii
    $s6  = "function O0O0O0O()" fullword ascii
    $s7  = "return O000O0O;" fullword ascii
    $s8  = "return o00o0O0;" fullword ascii
    $s9  = "return O0OOo0o;" fullword ascii
    $s10 = "O000O0O=(new Function(\"oO00ooO\",\"ooO0O00\",\"var OO0Oo0O=OO0O0oO(ooO0O00);return oOoOOoO(OO0Oo0O,oO00ooO);\")(4,\"eval\"));" fullword ascii
    $s11 = "function OO0O0oO(oOo00o0)" fullword ascii
    $s12 = "function oo0oOoo(OOOOO0o)" fullword ascii
    $s13 = "return oOoOoOo;" fullword ascii
    $s14 = "oOoOoOo=(new Function(\"o00OOoo\",\"O0oO000\",\"ooo0Oo0\",\"oOoOOOo\",\"return o00OOoo[Math[ooo0Oo0](Math[oOoOOOo]()*O0oO000)];" ascii
    $s15 = "return OOOoOOo^o0OoooO;" fullword ascii
    $s16 = ",O000oo0,new Array(1,2,\"floor\")[2],new Array(1,2,\"random\")[2]));" fullword ascii
    $s17 = "oOoOoOo=(new Function(\"o00OOoo\",\"O0oO000\",\"ooo0Oo0\",\"oOoOOOo\",\"return o00OOoo[Math[ooo0Oo0](Math[oOoOOOo]()*O0oO000)];" ascii
    $s18 = "oOO00oO=(new Function(\"OooOOo0\",\"oo0O0oo\",\"var O00ooOO=String[\\\"fromC\\\"+oo0O0oo](OooOOo0);return O00ooOO;\")(O00000O,ne" ascii
    $s19 = "function O0O00O0()" fullword ascii
    $s20 = "function OOOOooO(oo000OO)" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}