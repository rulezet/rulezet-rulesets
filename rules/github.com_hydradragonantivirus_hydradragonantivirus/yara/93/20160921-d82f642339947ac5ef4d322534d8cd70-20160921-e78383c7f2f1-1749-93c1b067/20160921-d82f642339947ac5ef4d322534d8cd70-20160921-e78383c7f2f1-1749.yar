rule _20160921_d82f642339947ac5ef4d322534d8cd70_20160921_e78383c7f2f1_1749 {
  meta:
    description = "datamaliciousorder - from files 20160921_d82f642339947ac5ef4d322534d8cd70.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"
    hash2       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"

  strings:
    $s1  = "(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";}" ascii
    $s2  = "uck(){return \"Ot\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq" ascii
    $s3  = "fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo" ascii
    $s4  = "),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(" ascii
    $s5  = "k(){return \"Np\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\"" ascii
    $s6  = "(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ik\";}" ascii
    $s7  = "\"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s8  = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"CCb\";})(" ascii
    $s9  = "on fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s10 = "ion fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s11 = "(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}