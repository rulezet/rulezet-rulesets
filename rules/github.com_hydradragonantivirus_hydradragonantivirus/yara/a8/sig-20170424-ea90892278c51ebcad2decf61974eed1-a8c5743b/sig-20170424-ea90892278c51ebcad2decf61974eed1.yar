rule sig_20170424_ea90892278c51ebcad2decf61974eed1 {
  meta:
    description = "datamaliciousorder - file 20170424_ea90892278c51ebcad2decf61974eed1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b3c05bba6109e66cf7d06e18ec591c89ddf3218a6e20d65f2640ff3391db6d3"

  strings:
    $s1  = "return oOooooO;" fullword ascii
    $s2  = ",o0O000O,new Array(1,2,\"floor\")[2],new Array(1,2,\"random\")[2]));" fullword ascii
    $s3  = "function OOOOOOO(oOoO000)" fullword ascii
    $s4  = "o00o0oO=(new Function(\"O00oOoo\",\"oOOo00o\",\"var Oo00O0O=String[\\\"fromC\\\"+oOOo00o](O00oOoo);return Oo00O0O;\")(OoOOo00,ne" ascii
    $s5  = "ooo0o0O=(new Function(\"OoooooO\",\"oo00oOo\",\"O0o0o00\",\"O00OOo0\",\"return OoooooO[Math[O0o0o00](Math[O00OOo0]()*oo00oOo)];" ascii
    $s6  = "return ooo0o0O;" fullword ascii
    $s7  = "function oOO0OOo(ooo00oO)" fullword ascii
    $s8  = "o00o0oO=(new Function(\"O00oOoo\",\"oOOo00o\",\"var Oo00O0O=String[\\\"fromC\\\"+oOOo00o](O00oOoo);return Oo00O0O;\")(OoOOo00,ne" ascii
    $s9  = "function O0O0oo0()" fullword ascii
    $s10 = "O0oooOO=(new Function(\"o0ooOoo\",\"o0oOoOO\",\"Oo0Oo00=/\\\\S{1}/g;return o0ooOoo[o0oOoOO](Oo0Oo00);\")(ooo00oO,new Array(1,\"m" ascii
    $s11 = "return O00o0oO;" fullword ascii
    $s12 = "ooo0o0O=(new Function(\"OoooooO\",\"oo00oOo\",\"O0o0o00\",\"O00OOo0\",\"return OoooooO[Math[O0o0o00](Math[O00OOo0]()*oo00oOo)];" ascii
    $s13 = "function o0OOo0O(o00O00o)" fullword ascii
    $s14 = "return O0oooOO;" fullword ascii
    $s15 = "function O00ooO0(o0oo0oO,o0O000O)" fullword ascii
    $s16 = "OOO0O0O=(new Function(\"O0o0Ooo\",\"oOO00Oo\",\"var OOO00oo=oOO0OOo(oOO00Oo);return O00ooO0(OOO00oo,O0o0Ooo);\")(4,\"eval\"));" fullword ascii
    $s17 = "O0oooOO=(new Function(\"o0ooOoo\",\"o0oOoOO\",\"Oo0Oo00=/\\\\S{1}/g;return o0ooOoo[o0oOoOO](Oo0Oo00);\")(ooo00oO,new Array(1,\"m" ascii
    $s18 = "return OOO0O0O;" fullword ascii
    $s19 = "return ooO0o0o^OOOo0oO;" fullword ascii
    $s20 = "O00o0oO=(new Function(\"O0oO0Oo\",\"OoO0O0o\",\"var o0O00OO=new Array(3,63,232,73,212,157,136,59,233,14,42,219,211,195,226,64),O" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}