rule _20160517_54805e10b3733715c51a94776af549ec_20160517_f8dddebde3da_1078 {
  meta:
    description = "datamaliciousorder - from files 20160517_54805e10b3733715c51a94776af549ec.js, 20160517_f8dddebde3dafc83676580cb89691994.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ce37c575e8d06d14067273b847052793a69f071dd24923ed351c1a7332c8a2d"
    hash2       = "ffa8d61378480e77ee6677323ddf4aa910926ed838cff309d41daf6860ef53f1"

  strings:
    $s1 = "var nConverts1 /* U  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* U  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* U  */;};" fullword ascii
    $s4 = "var enjoy1 /* U  */ = false;" fullword ascii
    $s5 = "batch =/* U  */ \"R\" + \"esponseB\"/* U  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s6 = "could = /* U  */(/* U  */\"noitisop\").split(''/* U  */).reverse(/* U  */).join('');" fullword ascii
    $s7 = "enjoy1 /* U  */ /* U  */= true;/* U  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}