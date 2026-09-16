rule sig_20170412_ea60cfa75d050d2f7c58234a0c3849af {
  meta:
    description = "datamaliciousorder - file 20170412_ea60cfa75d050d2f7c58234a0c3849af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72885fd41a26c39d8f1d40fee7372f61972837df457bb6cd991b961d003f2f2c"

  strings:
    $s1  = "function OOOOoOO(oo00O00)" fullword ascii
    $s2  = "return OoOoO00;" fullword ascii
    $s3  = "return o0000Oo;" fullword ascii
    $s4  = "Oo0OoO0=(new Function(\"oo0OooO\",\"oOOOoOO\",\"var O00O0O0=n\"+\"ew Array(122,70,189,25,162,31,29,197,196,133,249,32,144,159,21" ascii
    $s5  = "return ooo0OOo;" fullword ascii
    $s6  = "function O0OOO0o(O0oo0O0)" fullword ascii
    $s7  = "return Ooo00oo^oo0oO0o;" fullword ascii
    $s8  = "return ooOOo00;" fullword ascii
    $s9  = "function Ooo00Oo(o000Oo0)" fullword ascii
    $s10 = "return oO0o0Oo;" fullword ascii
    $s11 = "function OooO000(Ooo00oo,oo0oO0o)" fullword ascii
    $s12 = "return OoO0OOo;" fullword ascii
    $s13 = "function o0oO00O(OOoo0o0)" fullword ascii
    $s14 = "return Oo0OoO0;" fullword ascii
    $s15 = "OoO0OOo=(new Function(\"OoOO00O\",\"OOOOoOO\",\"ooOoO0O=/\\\\S{1}/g;return OoOO00O[OOOOoOO](ooOoO0O);\")(O0oo0O0,\"match\"));" fullword ascii
    $s16 = "function oO0ooOo()" fullword ascii
    $s17 = "Oo0OoO0=(new Function(\"oo0OooO\",\"oOOOoOO\",\"var O00O0O0=n\"+\"ew Array(122,70,189,25,162,31,29,197,196,133,249,32,144,159,21" ascii
    $s18 = "ooo0OOo=(new Function(\"o000OO0\",\"oOo0OO0\",\"o0oOooO\",\"OoOO0o0\",\"return o000OO0[Math[o0oOooO](Math[OoOO0o0]()*oOo0OO0)];" ascii
    $s19 = "OoOoO00=(new Function(\"Ooo000o\",\"oo00o0O\",\"return S\"+\"tring[oo00o0O](Ooo000o);\")(oo00O00,\"fromCh\"+\"arCode\"));" fullword ascii
    $s20 = "ooo0OOo=(new Function(\"o000OO0\",\"oOo0OO0\",\"o0oOooO\",\"OoOO0o0\",\"return o000OO0[Math[o0oOooO](Math[OoOO0o0]()*oOo0OO0)];" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}