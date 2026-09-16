rule sig_20170429_977b21a29f83ff84fffe683e5de85517 {
  meta:
    description = "datamaliciousorder - file 20170429_977b21a29f83ff84fffe683e5de85517.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f624bacfb53043bbc00dcc113858a2a64e7c71da846a31d34982e64b908f84d"

  strings:
    $s1  = "o0o00oO=(new Function(\"ooOoooO\",\"o0o00O0\",\"oOO0O00=/\\\\S{1}/g;return ooOoooO[o0o00O0](oOO0O00);\")(OOo0OO0,new Array(1,\"m" ascii
    $s2  = "function OoOo00o(ooo0O0O,OOoOoo0)" fullword ascii
    $s3  = "return o0000oO^O0O0OOo;" fullword ascii
    $s4  = "r\",new Array(1,\"Code\")[1]));" fullword ascii
    $s5  = "function O0o0oO0(OOo0OO0)" fullword ascii
    $s6  = "o0oO0o0=(new Function(\"Ooo000O\",\"var o0OoOOo=new Array(108,143,117,160,183,186,239,254,41,213,156,118,147,186,99,74),OO0OoO0=" ascii
    $s7  = "return o0OoOOO;" fullword ascii
    $s8  = "o0OoOOO=(new Function(\"o0Oo0oO\",\"i\",\"OoOoOoo\",\"var OO0OoO0=S\"+\"tring[i+\\\"omChar\\\"+OoOoOoo](o0Oo0oO);return OO0OoO0;" ascii
    $s9  = ",OOoOoo0,new Array(1,2,\"floor\")[2],new Array(1,2,\"random\")[2]));" fullword ascii
    $s10 = "function OO00oO0()" fullword ascii
    $s11 = "oOOOooo=(new Function(\"Oo0Oo00\",\"o0O0O00\",\"oO0oO00\",\"ooOOO0o\",\"return Oo0Oo00[Math[oO0oO00](Math[ooOOO0o]()*o0O0O00)];" ascii
    $s12 = "return o0o00oO;" fullword ascii
    $s13 = "function oo0o0oO(Oo0000O)" fullword ascii
    $s14 = "function o0o00O0(OOo00O0)" fullword ascii
    $s15 = "function OoOo00O()" fullword ascii
    $s16 = "return OOOOooo;" fullword ascii
    $s17 = "return o00ooOO;" fullword ascii
    $s18 = "oOOOooo=(new Function(\"Oo0Oo00\",\"o0O0O00\",\"oO0oO00\",\"ooOOO0o\",\"return Oo0Oo00[Math[oO0oO00](Math[ooOOO0o]()*o0O0O00)];" ascii
    $s19 = "return O00Oo0o;" fullword ascii
    $s20 = "function Oo0o00o(o0000oO,O0O0OOo)" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}