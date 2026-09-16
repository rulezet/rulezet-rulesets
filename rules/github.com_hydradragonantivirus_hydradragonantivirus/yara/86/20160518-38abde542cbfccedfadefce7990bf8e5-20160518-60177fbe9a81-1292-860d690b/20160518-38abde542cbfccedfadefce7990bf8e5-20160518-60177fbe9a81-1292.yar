rule _20160518_38abde542cbfccedfadefce7990bf8e5_20160518_60177fbe9a81_1292 {
  meta:
    description = "datamaliciousorder - from files 20160518_38abde542cbfccedfadefce7990bf8e5.js, 20160518_60177fbe9a81fa7c1df2b48cc013d076.js, 20160518_9c53ca88dab5dccf556a2c034dd304df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b49b6b5bedf083ce6d5df0dea4813a9ff63f4b2325f2278a6ea225e43bf3e6b"
    hash2       = "c6857c8bc5ba697b03f21c401b503e28d77008342b9c3aedb6033648b344867a"
    hash3       = "47ca71d6077b975a9dfc6230d66367ef0404ebbf51cefa2c762953293bd1d5c4"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* L  */, dingy, (true, false));" fullword ascii
    $s2 = "dot1 /* L  */= true;/* L  */" fullword ascii
    $s3 = "function sDiv2(){return newtonsCradle0 /* L  */;};" fullword ascii
    $s4 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* L  */, A8name /* L  *" ascii
    $s5 = "newtonsCradle1 /* L  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}