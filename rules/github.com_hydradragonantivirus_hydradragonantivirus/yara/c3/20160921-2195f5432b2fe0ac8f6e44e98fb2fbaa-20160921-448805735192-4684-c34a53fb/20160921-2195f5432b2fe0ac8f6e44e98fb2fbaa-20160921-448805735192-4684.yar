rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_448805735192_4684 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_44880573519212a90b7d910319fc31d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"

  strings:
    $s1 = "return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s2 = "n \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";})(),(func" ascii
    $s3 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"N" ascii
    $s4 = "(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Np\";}" ascii
    $s5 = "{return \"DHd\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}