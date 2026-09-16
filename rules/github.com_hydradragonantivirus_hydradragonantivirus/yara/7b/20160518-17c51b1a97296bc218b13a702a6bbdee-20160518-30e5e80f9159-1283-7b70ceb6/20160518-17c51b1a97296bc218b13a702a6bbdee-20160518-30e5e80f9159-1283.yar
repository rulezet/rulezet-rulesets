rule _20160518_17c51b1a97296bc218b13a702a6bbdee_20160518_30e5e80f9159_1283 {
  meta:
    description = "datamaliciousorder - from files 20160518_17c51b1a97296bc218b13a702a6bbdee.js, 20160518_30e5e80f9159585bba57008cda45ccd0.js, 20160518_9c2a855351b060468854399bc7e64c02.js, 20160519_6f3cb9c930d968531983bf27a1d8440f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7127d8231c0c9941774defcd351bf9b868f86aef03f43fa1bdb9c76caa0b7c48"
    hash2       = "297e0b13174a453c263c58dab2239a5ad0062ae3dae33844cb29eddb947538b0"
    hash3       = "785d701802326cb4ed67a0d0a84c178a2e3a27b416091f54995ea8be46d50d55"
    hash4       = "203929867148d7df6d35d7ce03eb8acef62c416899196f672e0cad4872e4bdd5"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* R  */, dingy, (true, false));" fullword ascii
    $s2 = "dot1 /* R  */= true;/* R  */" fullword ascii
    $s3 = "function sDiv2(){return newtonsCradle0 /* R  */;};" fullword ascii
    $s4 = "newtonsCradle1 /* R  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* R  */, A8name /* R  *" ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}