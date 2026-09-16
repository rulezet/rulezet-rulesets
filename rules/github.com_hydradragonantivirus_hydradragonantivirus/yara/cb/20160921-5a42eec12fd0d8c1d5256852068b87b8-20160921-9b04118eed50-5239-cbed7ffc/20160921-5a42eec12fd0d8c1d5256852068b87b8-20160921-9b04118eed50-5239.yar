rule _20160921_5a42eec12fd0d8c1d5256852068b87b8_20160921_9b04118eed50_5239 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_9b04118eed50c5e7331c4157a5c4dfc8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash2       = "fdb29344d617d9ae88ae6d7109bec25567e1c486cbb28c248a65e9f2a678c75d"

  strings:
    $s1 = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s2 = "k(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\"" ascii
    $s3 = "n fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s4 = " fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"U" ascii
    $s5 = "eturn \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}