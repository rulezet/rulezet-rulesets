rule _20160517_34f021cbd4e503e22e83e68644bb999e_20160517_c0a8743bab82_1071 {
  meta:
    description = "datamaliciousorder - from files 20160517_34f021cbd4e503e22e83e68644bb999e.js, 20160517_c0a8743bab8299108c7b4cc3131ff10c.js, 20160517_f7563c69f97231393be1b3a0c9164b83.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f933e9c1f682f6d3c62c414f7fa9cd7b04fc7cdcf604861c885ea786f787f10"
    hash2       = "4616e8bc127defa129d9e2b19e5491371650d24dd0daee729dfc9ee3ea39aa3e"
    hash3       = "f5448eefe0da0f448167ea1df6891a55fa4cab76d8ecaf46ef14e1fa2d46e99f"

  strings:
    $s1 = "var nConverts1 /* B  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* B  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* B  */;};" fullword ascii
    $s4 = "var enjoy1 /* B  */ = false;" fullword ascii
    $s5 = "could = /* B  */(/* B  */\"noitisop\").split(''/* B  */).reverse(/* B  */).join('');" fullword ascii
    $s6 = "batch =/* B  */ \"R\" + \"esponseB\"/* B  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s7 = "enjoy1 /* B  */ /* B  */= true;/* B  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}