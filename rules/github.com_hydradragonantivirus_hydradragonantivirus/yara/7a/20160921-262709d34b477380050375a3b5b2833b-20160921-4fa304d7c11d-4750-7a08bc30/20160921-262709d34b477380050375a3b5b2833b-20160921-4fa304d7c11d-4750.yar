rule _20160921_262709d34b477380050375a3b5b2833b_20160921_4fa304d7c11d_4750 {
  meta:
    description = "datamaliciousorder - from files 20160921_262709d34b477380050375a3b5b2833b.js, 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2738de24af2af834f5ce43b4e99137d47cd1993ec0b6dc3c1071deb99efcd62c"
    hash2       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash3       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"

  strings:
    $s1 = "return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})()" ascii
    $s2 = "LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s3 = "n \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(func" ascii
    $s4 = "n fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"A" ascii
    $s5 = "s\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}