rule sig_20170403_6c283ccdc1983912dcee1f61787e03a7 {
  meta:
    description = "datamaliciousorder - file 20170403_6c283ccdc1983912dcee1f61787e03a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65f6ec44b89f77cb270c5d8389541ff381d186fd5856df8cf3155b521a9dcc8b"

  strings:
    $s1  = "OoO0oOO=(new Function(\"ooooO0o\",\"return ooooO0o['match'](/\\\\S{1}/g);\")(OOooO00));" fullword ascii
    $s2  = "return OooOOOO;" fullword ascii
    $s3  = "function O00oOOO(OO0OoOO)" fullword ascii
    $s4  = "function ooo0Oo0(OOOOoOo)" fullword ascii
    $s5  = "return Oo0o0OO;" fullword ascii
    $s6  = "return oOOoo00;" fullword ascii
    $s7  = "OOO00oo=(new Function(\"oo0O0O0\",\"return String.fromCharCode(oo0O0O0);\")(OO0OoOO));" fullword ascii
    $s8  = "function o000OO0(ooooOO0,oo0Oo0o)" fullword ascii
    $s9  = "o0oo0Oo=(new Function(\"oOoo00O\",\"OOO0o00\",\"return oOoo00O[Math.floor(Math.random()*OOO0o00)];\")(ooooOO0,oo0Oo0o));" fullword ascii
    $s10 = "oOOoo00=(new Function(\"var OOOO0OO=OOoO0OO(\\\"e+v+lave+la+eve+al\\\");return o000OO0(OOOO0OO,18);\")());" fullword ascii
    $s11 = "OooOOOO=(new Function(\"OOo0OO0\",\"return parseInt(OOo0OO0,16);\")(OOOOoOo));" fullword ascii
    $s12 = "Oo0o0OO=(new Function(\"OO00o0O\",\"var O0oO00o=\"+\"new Array(127,104,251,49,192,34,221,139,205,94,40,99,191,169,200,126),Oo00O" ascii
    $s13 = "return OO0o0o0;" fullword ascii
    $s14 = "Oo0o0OO=(new Function(\"OO00o0O\",\"var O0oO00o=\"+\"new Array(127,104,251,49,192,34,221,139,205,94,40,99,191,169,200,126),Oo00O" ascii
    $s15 = "function OOO0oOo()" fullword ascii
    $s16 = "return OoO0oOO;" fullword ascii
    $s17 = "return o0oo0Oo;" fullword ascii
    $s18 = "function OOoO0OO(OOooO00)" fullword ascii
    $s19 = "function o00O00o()" fullword ascii
    $s20 = "function O0oOo0O(OOO00Oo)" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}