rule _20160921_3282034bab74b3776acf585e8adfca92_20160921_5645898a54df_4873 {
  meta:
    description = "datamaliciousorder - from files 20160921_3282034bab74b3776acf585e8adfca92.js, 20160921_5645898a54dfcbd78b32ee6da656f545.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b99efa289490e150d7af72ae3e0fb067880b4a22c16ba75dec34f9945b5c2df"
    hash2       = "0d8d12c1edd9af4fca97f4e7013b538499acfb96d7d0bed0a7b5419e888829b1"

  strings:
    $s1 = "on fuck(){return \"DHd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s2 = ",(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){" ascii
    $s3 = "(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck" ascii
    $s4 = "k(){return \"Fv\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Xw\";" ascii
    $s5 = "nction fuck(){return \"Jo\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}