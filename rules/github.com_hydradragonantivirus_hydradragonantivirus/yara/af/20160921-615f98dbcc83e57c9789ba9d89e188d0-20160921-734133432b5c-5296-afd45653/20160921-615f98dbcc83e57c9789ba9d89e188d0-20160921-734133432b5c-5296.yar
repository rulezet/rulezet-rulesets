rule _20160921_615f98dbcc83e57c9789ba9d89e188d0_20160921_734133432b5c_5296 {
  meta:
    description = "datamaliciousorder - from files 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_734133432b5c6f9bde8604a5856b0226.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash2       = "ae166a3e50bde57db63d39eeb168b02f14d45f281093c1420136eb1293fd87ef"

  strings:
    $s1 = "ction fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retur" ascii
    $s2 = "\"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(func" ascii
    $s3 = "Pu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ar\";})(),(functio" ascii
    $s4 = "return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})()," ascii
    $s5 = "PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}