rule _20160517_206908ed46d74d1bd047917a09719f02_20160517_6beee55b9573_1067 {
  meta:
    description = "datamaliciousorder - from files 20160517_206908ed46d74d1bd047917a09719f02.js, 20160517_6beee55b9573c6898f85119eeda14902.js, 20160517_b4282ae02d884c3f37a601ff09ef8d1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a877bef3f1209a62bf88d56bdde17a36e6951e1f906d7059aceaf5d525babc17"
    hash2       = "57ac14756dde266a53ad85f09718b7fc15880c7d935e52aa1e153f6068ead432"
    hash3       = "74bba99e29ce3fbd63fe84227a927bd6af0a3c6bb5802d4db0e39f68d5012550"

  strings:
    $s1 = "var nConverts1 /* d  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* d  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* d  */;};" fullword ascii
    $s4 = "enjoy1 /* d  */ /* d  */= true;/* d  */" fullword ascii
    $s5 = "batch =/* d  */ \"R\" + \"esponseB\"/* d  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s6 = "could = /* d  */(/* d  */\"noitisop\").split(''/* d  */).reverse(/* d  */).join('');" fullword ascii
    $s7 = "var enjoy1 /* d  */ = false;" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}