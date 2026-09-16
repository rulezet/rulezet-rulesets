rule sig_20170408_7f8e4638cc644818f53f9138a0559378 {
  meta:
    description = "datamaliciousorder - file 20170408_7f8e4638cc644818f53f9138a0559378.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1686945817b88553e040394a4618f81843ed657aff104eac58551f20feaf8d"

  strings:
    $s1  = "return o0OO0O0;" fullword ascii
    $s2  = "o0ooOoo=(new Function(\"oO0o0O0\",\"OOoO00O\",\"O0OoOoo\",\"O0o0o0o\",\"return oO0o0O0[Math[O0OoOoo](Math[O0o0o0o]()*OOoO00O)];" ascii
    $s3  = "o0ooOoo=(new Function(\"oO0o0O0\",\"OOoO00O\",\"O0OoOoo\",\"O0o0o0o\",\"return oO0o0O0[Math[O0OoOoo](Math[O0o0o0o]()*OOoO00O)];" ascii
    $s4  = "return oo00o00;" fullword ascii
    $s5  = "return oOOoo0O;" fullword ascii
    $s6  = "return o0ooO00^ooOOOoo;" fullword ascii
    $s7  = "oOOoo0O=(new Function(\"OoooOOO\",\"return p\"+\"arseInt(OoooOOO,16);\")(oOO0Oo0));" fullword ascii
    $s8  = "ooo0oO0=(new Function(\"O0o00OO\",\"var O0oO0Oo=OO000OO(\\\"evalll\\\");return ooOOO00(O0oO0Oo,O0o00OO);\")(6));" fullword ascii
    $s9  = "o0OO0O0=(new Function(\"o0OOoo0\",\"return o0OOoo0['match'](/\\\\S{1}/g);\")(O0oo0OO));" fullword ascii
    $s10 = "function oOo0000(o00oo0o)" fullword ascii
    $s11 = "return oo0Oo0o;" fullword ascii
    $s12 = "function OO000OO(O0oo0OO)" fullword ascii
    $s13 = "function oo0OOO0(OoOoooO)" fullword ascii
    $s14 = "return ooo0oO0;" fullword ascii
    $s15 = "return Ooo0Ooo;" fullword ascii
    $s16 = "function ooOOO00(o0oOO00,OooO0O0)" fullword ascii
    $s17 = "oo0Oo0o=(new Function(\"O00OO0O\",\"var oOo0OOo=\"+\"new Array(46,85,79,61,124,180,185,79,243,208,127,81,193,118,47,83),o0000O0=" ascii
    $s18 = "function oOo000o(oOO0Oo0)" fullword ascii
    $s19 = "return o0ooOoo;" fullword ascii
    $s20 = "oo0Oo0o=(new Function(\"O00OO0O\",\"var oOo0OOo=\"+\"new Array(46,85,79,61,124,180,185,79,243,208,127,81,193,118,47,83),o0000O0=" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}