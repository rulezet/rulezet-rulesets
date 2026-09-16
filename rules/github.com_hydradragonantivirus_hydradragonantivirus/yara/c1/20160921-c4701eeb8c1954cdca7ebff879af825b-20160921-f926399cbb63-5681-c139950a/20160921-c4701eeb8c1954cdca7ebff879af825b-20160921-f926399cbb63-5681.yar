rule _20160921_c4701eeb8c1954cdca7ebff879af825b_20160921_f926399cbb63_5681 {
  meta:
    description = "datamaliciousorder - from files 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash2       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = "n \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(fu" ascii
    $s2 = "uck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"GNm" ascii
    $s3 = "function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){re" ascii
    $s4 = "DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s5 = "(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}