rule _20160921_2f8fa7cee8a6f4f78978b7417f3f700e_20160921_6db2cb585eb9_3590 {
  meta:
    description = "datamaliciousorder - from files 20160921_2f8fa7cee8a6f4f78978b7417f3f700e.js, 20160921_6db2cb585eb933d83d07b47d979b00ec.js, 20160921_91af5c220d1ea27d72d05f472ba8fa16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6410122a95cd840a4eef622389d8026475b4f6a156d4b5288cf227165c036c96"
    hash2       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"
    hash3       = "d8a5c3b8bd7307238c3f0a133635143674d5db84b7c5615a145a8bea310c68de"

  strings:
    $s1 = "rn \"Cd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s2 = "Cr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s3 = "function fuck(){return \"XHj\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){r" ascii
    $s4 = ")(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(" ascii
    $s5 = "uck(){return \"Cd\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DRx" ascii
    $s6 = "k(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}