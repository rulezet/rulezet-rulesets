rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_448805735192_4689 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_7e15ac2755366d4644a83de8ec9c1a47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash3       = "97eaf7c50f22bfc94f97a02e5e83a8f1fb3583717fb9f4a6666ae882ea4d6f55"

  strings:
    $s1 = "n \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(fun" ascii
    $s2 = "fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"J" ascii
    $s3 = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo\";})(),(fu" ascii
    $s4 = "){return \"ZWu\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})" ascii
    $s5 = "ck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}