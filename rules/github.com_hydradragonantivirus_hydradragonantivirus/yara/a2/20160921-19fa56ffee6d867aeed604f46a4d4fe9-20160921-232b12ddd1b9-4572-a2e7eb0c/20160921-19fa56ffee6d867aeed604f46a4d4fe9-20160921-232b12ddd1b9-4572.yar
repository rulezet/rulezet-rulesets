rule _20160921_19fa56ffee6d867aeed604f46a4d4fe9_20160921_232b12ddd1b9_4572 {
  meta:
    description = "datamaliciousorder - from files 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash2       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash3       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"
    hash4       = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"

  strings:
    $s1 = "ion fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s2 = "){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";" ascii
    $s3 = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s4 = "fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz" ascii
    $s5 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}