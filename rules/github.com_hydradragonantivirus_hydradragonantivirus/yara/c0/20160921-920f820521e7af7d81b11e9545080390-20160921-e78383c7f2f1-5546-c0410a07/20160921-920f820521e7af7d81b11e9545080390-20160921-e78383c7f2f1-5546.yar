rule _20160921_920f820521e7af7d81b11e9545080390_20160921_e78383c7f2f1_5546 {
  meta:
    description = "datamaliciousorder - from files 20160921_920f820521e7af7d81b11e9545080390.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4a6a94fe43f214f35574405d899a6d61259c2b1135c1ecf399630de11c6dea3"
    hash2       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"

  strings:
    $s1 = "(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){r" ascii
    $s2 = "ction fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii
    $s3 = ")(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck" ascii
    $s4 = "n fuck(){return \"Et\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s5 = "n \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Np\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}