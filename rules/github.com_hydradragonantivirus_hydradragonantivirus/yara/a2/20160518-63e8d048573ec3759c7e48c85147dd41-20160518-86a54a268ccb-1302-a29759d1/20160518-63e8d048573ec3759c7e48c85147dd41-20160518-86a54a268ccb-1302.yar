rule _20160518_63e8d048573ec3759c7e48c85147dd41_20160518_86a54a268ccb_1302 {
  meta:
    description = "datamaliciousorder - from files 20160518_63e8d048573ec3759c7e48c85147dd41.js, 20160518_86a54a268ccb7ff46882f20a68c7464c.js, 20160518_8be16ef5dad5aa2f984de7d4e00e623c.js, 20160518_fb86a30f98ff1bfb8de22b38c3d36de4.js, 20160519_8d3f010d3bd94d3f85280e59655f5a23.js, 20160519_a300ec40c4e1861dd7189fc756190fc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c836fb202610a0e7e22f4663a0d9c2a7d4347650e541251b044ee0adb96f8efa"
    hash2       = "34355d00956b5548e6d7afa466b8a6cf3c3cd43a46d6f06275d91f50c58465ad"
    hash3       = "1ef1694fcdc4f5b989737cb3dcfe5cb534b16eb1227fdc342b4d1d50c5349c34"
    hash4       = "7f605e1b9a7ff9cb9359f8de8a05336b93755e471c4456182e3de9b1bb714d20"
    hash5       = "ce3ce5a48b2936aea1fee4541afec2ff2adb5154b13c7f294a276b987c803497"
    hash6       = "f5ba0da86581b32d9e9abd2a60cedd79fe9b39607d2ef828e272e81c7e069d17"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* E  */, dingy, (true, false));" fullword ascii
    $s2 = "newtonsCradle1 /* E  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s3 = "dot1 /* E  */= true;/* E  */" fullword ascii
    $s4 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* E  */, A8name /* E  *" ascii
    $s5 = "function sDiv2(){return newtonsCradle0 /* E  */;};" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}