rule _20160518_557c4231bb467ff41be53bf2be63092a_20160519_3102e9d68379_1298 {
  meta:
    description = "datamaliciousorder - from files 20160518_557c4231bb467ff41be53bf2be63092a.js, 20160519_3102e9d68379aacc244b3e9cc83635e2.js, 20160519_dca96a675a70a4db418671e9acad31e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f63398491f7c363d6de7ae9944ae23ba9f14d7a75851ce85a6fa87fb0dc72b4e"
    hash2       = "032631dfa683eb126e1a9b1c658720da2b2b31e056bdcf79d1f500959e8c7120"
    hash3       = "5baa38dd6087f69c8abcb029402da4220dcd023d3b65c99326ed51a12dbdce15"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* A  */, dingy, (true, false));" fullword ascii
    $s2 = "function sDiv2(){return newtonsCradle0 /* A  */;};" fullword ascii
    $s3 = "dot1 /* A  */= true;/* A  */" fullword ascii
    $s4 = "newtonsCradle1 /* A  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* A  */, A8name /* A  *" ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}