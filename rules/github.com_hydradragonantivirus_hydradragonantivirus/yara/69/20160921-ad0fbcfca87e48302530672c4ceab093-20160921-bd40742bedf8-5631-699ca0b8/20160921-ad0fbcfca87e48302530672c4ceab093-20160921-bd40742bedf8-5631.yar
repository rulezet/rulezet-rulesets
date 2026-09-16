rule _20160921_ad0fbcfca87e48302530672c4ceab093_20160921_bd40742bedf8_5631 {
  meta:
    description = "datamaliciousorder - from files 20160921_ad0fbcfca87e48302530672c4ceab093.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"
    hash2       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"

  strings:
    $s1 = " fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s2 = "k(){return \"MBg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";" ascii
    $s3 = "(){return \"FJs\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";}" ascii
    $s4 = "n \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(fun" ascii
    $s5 = "{return \"DHd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}