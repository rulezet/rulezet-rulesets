rule _20160921_105b4651b7160ca47c8bc86d4da31c43_20160921_3ec558d1fbbb_4389 {
  meta:
    description = "datamaliciousorder - from files 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_5230866e44eda4e054d929933fdfdae1.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash2       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash3       = "4b11d10d6c2a935fa29f47c13ee54d426aac8d667f3bc2f79681ac7e4d365c76"
    hash4       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"

  strings:
    $s1 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"CCb\";})(),(function fu" ascii
    $s2 = "ion fuck(){return \"Ug\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"" ascii
    $s3 = "tion fuck(){return \"Wo0\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s4 = "(){return \"CTm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";" ascii
    $s5 = "return \"DAa\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}