rule sig_20160915_12357c7d1c84c94421dbe2ea7c88cd3a {
  meta:
    description = "datamaliciousorder - file 20160915_12357c7d1c84c94421dbe2ea7c88cd3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c23e28e0888108459b240c1cea692f8127fd46b117504cc7de106f1a4dbeffc0"

  strings:
    $s1  = "function zfohuqkogvefc7() {" fullword ascii
    $s2  = "function ybadjavufb4() {" fullword ascii
    $s3  = "return ojawguls5;" fullword ascii
    $s4  = "return fjygicvu4;" fullword ascii
    $s5  = "function zocsel4() {" fullword ascii
    $s6  = "return bervuz8;" fullword ascii
    $s7  = "function dirnyfwe0() {" fullword ascii
    $s8  = "function onumn0() {" fullword ascii
    $s9  = "return odecre7;" fullword ascii
    $s10 = "return ojgarnitni3;" fullword ascii
    $s11 = "function odhumsymxyhu1() {" fullword ascii
    $s12 = "function jvotesaw0() {" fullword ascii
    $s13 = "function pbedvivum0() {" fullword ascii
    $s14 = "return irebmytygo7;" fullword ascii
    $s15 = "return sumu9;" fullword ascii
    $s16 = "return axyc4;" fullword ascii
    $s17 = "return tysyb8;" fullword ascii
    $s18 = "return ymresi2;" fullword ascii
    $s19 = "function elmacxyme5() {" fullword ascii
    $s20 = "return lyjveqzaj0;" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    8 of them
}