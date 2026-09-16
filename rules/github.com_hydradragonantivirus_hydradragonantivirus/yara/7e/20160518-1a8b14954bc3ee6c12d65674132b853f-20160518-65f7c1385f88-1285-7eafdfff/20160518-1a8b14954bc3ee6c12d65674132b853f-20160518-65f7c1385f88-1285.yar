rule _20160518_1a8b14954bc3ee6c12d65674132b853f_20160518_65f7c1385f88_1285 {
  meta:
    description = "datamaliciousorder - from files 20160518_1a8b14954bc3ee6c12d65674132b853f.js, 20160518_65f7c1385f88ebcf71c6a8cde10212d5.js, 20160518_a59c6294406de20ad3296e8eed362274.js, 20160518_c3f401b77a81fbecb9efd1881eb2c3ca.js, 20160518_dd9340ee0e2f26c3cdc10b729fbf3984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c69f124751d0bb18f5f2c86a98f67523e1fb66cd1d4a62f6c0750da50727742"
    hash2       = "8e4ba9006fdd31aeee698dbc2d23dd53350edb9b53884eb7a9755b15c0a222d7"
    hash3       = "a122304843950fcf5e8f9f7ffdb81bd21b717f49ba8868c4d68d303ec21c7154"
    hash4       = "f67254f3cd0772a8d898ff35970fac90507652f1752d1b3baaed4d87e86473b7"
    hash5       = "2f4c768eb520704a5e8cda454b23a5c69e6be7e8085930d63d0425befed44fec"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* k  */, dingy, (true, false));" fullword ascii
    $s2 = "dot1 /* k  */= true;/* k  */" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* k  */, A8name /* k  *" ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* k  */;};" fullword ascii
    $s5 = "newtonsCradle1 /* k  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}