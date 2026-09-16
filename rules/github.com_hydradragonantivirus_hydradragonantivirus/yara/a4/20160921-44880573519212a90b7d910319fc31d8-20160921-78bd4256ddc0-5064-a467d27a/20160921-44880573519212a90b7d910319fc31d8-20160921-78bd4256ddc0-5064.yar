rule _20160921_44880573519212a90b7d910319fc31d8_20160921_78bd4256ddc0_5064 {
  meta:
    description = "datamaliciousorder - from files 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash2       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"

  strings:
    $s1 = "k(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";" ascii
    $s2 = "Ts\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(functio" ascii
    $s3 = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s4 = " fuck(){return \"IKv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AD" ascii
    $s5 = " \"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}