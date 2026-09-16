rule sig_20170425_b285a3b12d409401935ac3e83139f638 {
  meta:
    description = "datamaliciousorder - file 20170425_b285a3b12d409401935ac3e83139f638.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a12f6c36563fd381ffd577604570b51a8ee5a40c1c8aca07dbd7e16c22bd3aa"

  strings:
    $s1  = "oo0oO00=(new Function(\"o0oOO0o\",\"OO0O0o0\",\"ooO00oo=/\\\\S{1}/g;return o0oOO0o[OO0O0o0](ooO00oo);\")(ooo0o0O,new Array(1,\"m" ascii
    $s2  = "return oooOo0o;" fullword ascii
    $s3  = "function oOo0OoO(oo0OO00,OooOo00)" fullword ascii
    $s4  = "return oOOoOoo;" fullword ascii
    $s5  = "return oOoOooo;" fullword ascii
    $s6  = "function Ooooo0o(ooo0o0O)" fullword ascii
    $s7  = "O00o000=(new Function(\"OOoo0O0\",\"return \\\"0x\\\"+OOoo0O0['toString']();\")(OOOoo0o));" fullword ascii
    $s8  = "oooOo0o=(new Function(\"ooOo0oO\",\"OOOOOo0\",\"OO00O0o\",\"OOoO0Oo\",\"return ooOo0oO[Math[OO00O0o](Math[OOoO0Oo]()*OOOOOo0)];" ascii
    $s9  = "oOOoOoo=(new Function(\"OOOO0oO\",\"OOOOo0o\",\"var oOOoo00=S\"+\"tring[\\\"fr\\\"+OOOOo0o](OOOO0oO);return oOOoo00;\")(oo0oOO0," ascii
    $s10 = "oOoOooo=(new Function(\"oO0O0oo\",\"OOO0Ooo\",\"var OO00OOo=new Array(11,225,25,35,130,78,250,78,154,79,74,10,222,247,103,3),oOO" ascii
    $s11 = "O0OO00O=(new Function(\"Oo0OoOo\",\"oO0Oo0o\",\"var OOooO0o=Ooooo0o(oO0Oo0o);return oOoOoo0(OOooO0o,Oo0OoOo);\")(4,\"eval\"));" fullword ascii
    $s12 = "return O00o000;" fullword ascii
    $s13 = "return O00o0oo;" fullword ascii
    $s14 = "function OOo0ooO(oO00oo0)" fullword ascii
    $s15 = "function oOoOOoO()" fullword ascii
    $s16 = "function oO0oOo0()" fullword ascii
    $s17 = "oo0oO00=(new Function(\"o0oOO0o\",\"OO0O0o0\",\"ooO00oo=/\\\\S{1}/g;return o0oOO0o[OO0O0o0](ooO00oo);\")(ooo0o0O,new Array(1,\"m" ascii
    $s18 = "function OO0O0o0(oo0oOO0)" fullword ascii
    $s19 = "function oOoOoo0(OOO0O00,OOO0Oo0)" fullword ascii
    $s20 = "oOOoOoo=(new Function(\"OOOO0oO\",\"OOOOo0o\",\"var oOOoo00=S\"+\"tring[\\\"fr\\\"+OOOOo0o](OOOO0oO);return oOOoo00;\")(oo0oOO0," ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}