rule _20160517_4a06f45a2f0a2008dd370436945e85b7_20160517_75908c35bddf_1074 {
  meta:
    description = "datamaliciousorder - from files 20160517_4a06f45a2f0a2008dd370436945e85b7.js, 20160517_75908c35bddf1bd4e4ac8006ef168cd8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af3c708e2f776bb15eecd924122539b8d4308a0ba641bdb383f47f5bac8b38cd"
    hash2       = "59ef5dc6c53221fa3062ff36059653b867a28ad36fa9078b53ad3e9473a66588"

  strings:
    $s1 = "var nConverts1 /* J  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* J  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* J  */;};" fullword ascii
    $s4 = "could = /* J  */(/* J  */\"noitisop\").split(''/* J  */).reverse(/* J  */).join('');" fullword ascii
    $s5 = "var enjoy1 /* J  */ = false;" fullword ascii
    $s6 = "batch =/* J  */ \"R\" + \"esponseB\"/* J  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s7 = "enjoy1 /* J  */ /* J  */= true;/* J  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}