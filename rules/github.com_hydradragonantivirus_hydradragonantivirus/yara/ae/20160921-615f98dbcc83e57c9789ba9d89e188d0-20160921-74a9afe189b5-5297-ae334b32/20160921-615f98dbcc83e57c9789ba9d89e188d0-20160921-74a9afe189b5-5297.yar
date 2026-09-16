rule _20160921_615f98dbcc83e57c9789ba9d89e188d0_20160921_74a9afe189b5_5297 {
  meta:
    description = "datamaliciousorder - from files 20160921_615f98dbcc83e57c9789ba9d89e188d0.js, 20160921_74a9afe189b59f0b8148a7f92f42b125.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"
    hash2       = "5ce6bfd72ee0a8f8259b2cfbaa6f5b49ec72ab64b03caf4bd2a4f733ef96925b"

  strings:
    $s1 = "rn \"GJx\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s2 = ")(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s3 = "k(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\"" ascii
    $s4 = "turn \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})()" ascii
    $s5 = "urn \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}