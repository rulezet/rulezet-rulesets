rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_3b2083afdb57_4216 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_3b2083afdb57ae7e611f6f42c6787c73.js, 20160921_a05dfc337c4ada28e05759b304eef904.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "4c81783a1510b3172e1702365554b0e2000709a4e4217a8970aa381c9b357e36"
    hash3       = "db6a3cf7e8281867bf38b22cce5a945336377679a1a85ee91d365e41ec94182c"
    hash4       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash5       = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash6       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Mw\";})(),(fun" ascii
    $s2 = "y\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s3 = "(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"GNm\";" ascii
    $s4 = "function fuck(){return \"SUi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){r" ascii
    $s5 = ",(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}