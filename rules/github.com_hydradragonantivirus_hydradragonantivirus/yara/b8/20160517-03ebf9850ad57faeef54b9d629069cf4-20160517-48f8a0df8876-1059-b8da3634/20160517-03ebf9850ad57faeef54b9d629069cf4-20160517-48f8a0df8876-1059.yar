rule _20160517_03ebf9850ad57faeef54b9d629069cf4_20160517_48f8a0df8876_1059 {
  meta:
    description = "datamaliciousorder - from files 20160517_03ebf9850ad57faeef54b9d629069cf4.js, 20160517_48f8a0df887602820cafc8aa1ce3f696.js, 20160517_e0f25b61d1feca204f6ce5c850a7bf7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d44f1ab1dc1a1bacaf386c2259e884615452b1b4a49fd6dd97d035dfb9b38ee"
    hash2       = "633eab835d0a40000b3344e976e87598ad9bc69a93fb261823bad38ee6f892f3"
    hash3       = "86e110c6e86f099df925448c8173de597adacf835b17efe7ecd50e5879475f0b"

  strings:
    $s1 = "var nConverts1 /* x  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* x  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* x  */;};" fullword ascii
    $s4 = "batch =/* x  */ \"R\" + \"esponseB\"/* x  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s5 = "could = /* x  */(/* x  */\"noitisop\").split(''/* x  */).reverse(/* x  */).join('');" fullword ascii
    $s6 = "enjoy1 /* x  */ /* x  */= true;/* x  */" fullword ascii
    $s7 = "var enjoy1 /* x  */ = false;" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}