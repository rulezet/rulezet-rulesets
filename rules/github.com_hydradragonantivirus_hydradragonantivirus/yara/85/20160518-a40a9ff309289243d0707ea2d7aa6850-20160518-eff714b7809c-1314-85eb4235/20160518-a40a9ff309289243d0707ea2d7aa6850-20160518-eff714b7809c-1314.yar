rule _20160518_a40a9ff309289243d0707ea2d7aa6850_20160518_eff714b7809c_1314 {
  meta:
    description = "datamaliciousorder - from files 20160518_a40a9ff309289243d0707ea2d7aa6850.js, 20160518_eff714b7809c83016dae3916d3d285e0.js, 20160519_5accdb3f327a01524b6d67f1306fad2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f6cbb3c4f81cdbd181e7dd6a8e5d2b974261ca7a31bc653c6f9eb247dfe6ce0"
    hash2       = "089fe76a4bcc2bf0f6ee7583a93f5b3e96c0c477fdba5b4fef5460fb26e130f4"
    hash3       = "bc15a69507c2dffb69c4e97ade420020ebd4a910a4bb1b795360f4e5c4333546"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* i  */, dingy, (true, false));" fullword ascii
    $s2 = "function sDiv2(){return newtonsCradle0 /* i  */;};" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* i  */, A8name /* i  *" ascii
    $s4 = "newtonsCradle1 /* i  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "dot1 /* i  */= true;/* i  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}