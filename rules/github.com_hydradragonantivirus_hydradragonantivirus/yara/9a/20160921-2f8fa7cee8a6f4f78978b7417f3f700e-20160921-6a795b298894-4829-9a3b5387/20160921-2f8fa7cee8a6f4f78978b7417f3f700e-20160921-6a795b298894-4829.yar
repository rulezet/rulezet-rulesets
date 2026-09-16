rule _20160921_2f8fa7cee8a6f4f78978b7417f3f700e_20160921_6a795b298894_4829 {
  meta:
    description = "datamaliciousorder - from files 20160921_2f8fa7cee8a6f4f78978b7417f3f700e.js, 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_e8d738510e4d2e0efb6c7aa18a7a58d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6410122a95cd840a4eef622389d8026475b4f6a156d4b5288cf227165c036c96"
    hash2       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash3       = "e1cd4a36522d2ad8fc8435b6cb64d8e572d8b31d4203885fa375f539a3ea7891"

  strings:
    $s1 = "urn \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(f" ascii
    $s2 = "fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IP" ascii
    $s3 = " \"Hs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(fun" ascii
    $s4 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"D" ascii
    $s5 = "fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"A" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}