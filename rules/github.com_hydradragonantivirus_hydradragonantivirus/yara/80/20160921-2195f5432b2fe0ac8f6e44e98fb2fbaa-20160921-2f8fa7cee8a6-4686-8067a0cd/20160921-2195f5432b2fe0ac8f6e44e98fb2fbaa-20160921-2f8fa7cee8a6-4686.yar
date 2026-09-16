rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_2f8fa7cee8a6_4686 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_2f8fa7cee8a6f4f78978b7417f3f700e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "6410122a95cd840a4eef622389d8026475b4f6a156d4b5288cf227165c036c96"

  strings:
    $s1 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MIl\";})(" ascii
    $s2 = "urn \"Yk\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s3 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"XCr\";})(),(fu" ascii
    $s4 = "uck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s5 = "Ts\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ar\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}