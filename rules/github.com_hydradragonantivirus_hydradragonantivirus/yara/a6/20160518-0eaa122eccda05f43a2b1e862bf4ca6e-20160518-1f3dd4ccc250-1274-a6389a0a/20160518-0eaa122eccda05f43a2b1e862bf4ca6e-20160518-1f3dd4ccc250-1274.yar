rule _20160518_0eaa122eccda05f43a2b1e862bf4ca6e_20160518_1f3dd4ccc250_1274 {
  meta:
    description = "datamaliciousorder - from files 20160518_0eaa122eccda05f43a2b1e862bf4ca6e.js, 20160518_1f3dd4ccc25087ceddc9a63c207f9f86.js, 20160518_601a41b1356105896dc5bf23033191c9.js, 20160518_75a29bd2cfbf1a0f52e5a51dd49a36c3.js, 20160518_79c9035281a31b18b9eb9f27885af03e.js, 20160518_b92fdde5632086fcf22581d35a2b7abf.js, 20160518_d5692992c85a27e3e800a3737d0e2126.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca1cbc003738985f1bd6462a133f526b16c9b4ea890bc015e41d8df3988130f7"
    hash2       = "9d46e04c5deda19e56d4efebb59965f508ad0df8cadf7c3631b4b78df3a22585"
    hash3       = "2c86887bd3e97fd7e3386aab3bb4e0c280e8fa753b05436dd88d6669ae9bf431"
    hash4       = "bab1af4a02ac216467efefa716f4c49a59fff8d74234c9588a06490c209eafed"
    hash5       = "5c1baace8f9bc7ca6932c3f4257cab46e851da0b96eccf600bb36d9adab4de80"
    hash6       = "0da61639cf6e4a22dbcfca865610d7042531534b7fa0d6580ede9ac956edeedb"
    hash7       = "e1bd1c3e1d022553973b2eeb61cf80b9616cf3061f7f1773230f178b2238afa4"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* y  */, dingy, (true, false));" fullword ascii
    $s2 = "newtonsCradle1 /* y  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s3 = "function sDiv2(){return newtonsCradle0 /* y  */;};" fullword ascii
    $s4 = "dot1 /* y  */= true;/* y  */" fullword ascii
    $s5 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* y  */, A8name /* y  *" ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}