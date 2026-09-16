rule _20160921_2f8fa7cee8a6f4f78978b7417f3f700e_20160921_70b567ca258b_4830 {
  meta:
    description = "datamaliciousorder - from files 20160921_2f8fa7cee8a6f4f78978b7417f3f700e.js, 20160921_70b567ca258b3c505e14f3c712366f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6410122a95cd840a4eef622389d8026475b4f6a156d4b5288cf227165c036c96"
    hash2       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"

  strings:
    $s1 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){ret" ascii
    $s2 = "unction fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s3 = "urn \"MBg\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s4 = "),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){r" ascii
    $s5 = "ction fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}