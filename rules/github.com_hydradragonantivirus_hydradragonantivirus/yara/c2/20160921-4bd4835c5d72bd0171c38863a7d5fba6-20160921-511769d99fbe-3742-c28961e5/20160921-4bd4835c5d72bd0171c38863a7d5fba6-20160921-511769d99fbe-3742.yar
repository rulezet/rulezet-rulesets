rule _20160921_4bd4835c5d72bd0171c38863a7d5fba6_20160921_511769d99fbe_3742 {
  meta:
    description = "datamaliciousorder - from files 20160921_4bd4835c5d72bd0171c38863a7d5fba6.js, 20160921_511769d99fbe4d59a2e55781fb0eb77c.js, 20160921_82c6439487239a08e403c18f347e12e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34fcd9c1543d39dfd57d9c09da7c6123934388bbc0bf645db2a4dae174f514cc"
    hash2       = "2f4a69b097fb3d0d29d7f041be11cd2e8af137bd0ed525674079a1b7de28c7fd"
    hash3       = "db301ab72cd18ad4198865983d8e64e1840325c04d40cacaa8f5e2097faee094"

  strings:
    $s1 = "(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){" ascii
    $s2 = "{return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})()" ascii
    $s3 = "Nm\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(function" ascii
    $s4 = "ion fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return " ascii
    $s5 = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"CCb\";})(),(fun" ascii
    $s6 = "uck(){return \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}