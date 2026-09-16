rule _20160921_4bd4835c5d72bd0171c38863a7d5fba6_20160921_6a795b298894_5121 {
  meta:
    description = "datamaliciousorder - from files 20160921_4bd4835c5d72bd0171c38863a7d5fba6.js, 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_82c6439487239a08e403c18f347e12e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34fcd9c1543d39dfd57d9c09da7c6123934388bbc0bf645db2a4dae174f514cc"
    hash2       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash3       = "db301ab72cd18ad4198865983d8e64e1840325c04d40cacaa8f5e2097faee094"

  strings:
    $s1 = "unction fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){retu" ascii
    $s2 = "(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s3 = "uck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\"" ascii
    $s4 = "turn \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s5 = "\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}